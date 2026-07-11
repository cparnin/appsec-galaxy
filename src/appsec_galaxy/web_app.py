#!/usr/bin/env python3
"""
AppSec Galaxy - Web Interface

Web wrapper around the same scanner core the CLI and MCP server use, so
behaviour is identical across surfaces.

Usage:
    python web_app.py              # Start web server
    curl -X POST /scan             # API endpoint
"""

import os
import sys
import json
import asyncio
import subprocess
from pathlib import Path
from flask import Flask, request, jsonify, send_file, render_template, send_from_directory
from flask_cors import CORS
import logging
import hmac

# Add src directory to path so we can import existing modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import ALL existing functionality (no changes to existing code)
from appsec_galaxy.main import (
    validate_repo_path,
    validate_environment_config,
    run_security_scans,
    handle_auto_remediation,
    track_usage
)
from appsec_galaxy.reporting.html import generate_html_report

# Import path utilities for multi-repo output structure
from appsec_galaxy.path_utils import (
    get_output_path, cleanup_old_scans, setup_output_directories
)
from appsec_galaxy.config import BASE_OUTPUT_DIR
from appsec_galaxy.project_paths import IMAGES_DIR

# Configure logging for web app
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Flask app with template directory
app = Flask(__name__, template_folder='templates')

# Restrict CORS unless explicitly configured
cors_origins = [origin.strip() for origin in os.getenv("APPSEC_WEB_CORS_ORIGINS", "").split(",") if origin.strip()]
if cors_origins:
    CORS(app, resources={r"/*": {"origins": cors_origins}})
else:
    CORS(app)

# Global config (same as CLI)
WEB_CONFIG = None
LAST_SCAN_OUTPUT_DIR = None  # Track most recent scan output directory


def _is_sensitive_endpoint() -> bool:
    """Identify endpoints that should require API key protection when configured."""
    sensitive_routes = {
        'scan_repository',
        'get_html_report',
        'get_report_file',
        'get_dependency_health',
        'discover_repositories',
        'browse_directory',
        'get_current_directory',
    }
    return request.endpoint in sensitive_routes


@app.before_request
def enforce_api_key_for_sensitive_routes():
    """
    Enforce API key authentication for sensitive endpoints when APPSEC_WEB_API_KEY is configured.

    This protects scan execution and report retrieval APIs from unauthorized access.
    """
    expected_api_key = os.getenv("APPSEC_WEB_API_KEY", "")
    if not expected_api_key or not _is_sensitive_endpoint():
        return None

    supplied_api_key = request.headers.get("X-API-Key", "")
    if not supplied_api_key:
        return jsonify({'error': 'Missing API key'}), 401

    if not hmac.compare_digest(supplied_api_key, expected_api_key):
        return jsonify({'error': 'Invalid API key'}), 401

    return None


def _restore_env(name: str, original: str | None) -> None:
    """Put an env var back to its pre-scan value (or remove it)."""
    if original:
        os.environ[name] = original
    else:
        os.environ.pop(name, None)


def _directory_browsing_enabled() -> bool:
    """Return whether repository discovery and browse endpoints are enabled."""
    return os.getenv("APPSEC_ENABLE_DIRECTORY_BROWSING", "false").lower() == "true"

def init_web_config():
    """Initialize configuration using existing validation function."""
    global WEB_CONFIG
    if WEB_CONFIG is None:
        WEB_CONFIG = validate_environment_config()
    return WEB_CONFIG

@app.route('/images/<path:filename>', methods=['GET'])
def serve_image(filename: str):
    """Serve static image assets from the repo's images/ directory.

    Only whitelisted extensions and only files that actually live inside
    the images directory (no traversal); returns 404 for anything else.
    """
    from flask import abort
    allowed_ext = {'.png', '.jpg', '.jpeg', '.svg', '.webp', '.gif'}
    if not any(filename.lower().endswith(ext) for ext in allowed_ext):
        abort(404)
    images_dir = IMAGES_DIR
    target = (images_dir / filename).resolve()
    if not str(target).startswith(str(images_dir) + os.sep) or not target.is_file():
        abort(404)
    return send_from_directory(str(images_dir), filename)


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for deployment monitoring."""
    return jsonify({
        'status': 'healthy',
        'service': 'AppSec Galaxy Web API',
        'version': '1.0.0'
    })

@app.route('/config', methods=['GET'])
def get_config():
    """Get current scanner configuration."""
    from appsec_galaxy.scanners.ai_scanner import (
        PROVIDER_KEY_ENV, SUPPORTED_PROVIDERS, get_default_model,
    )

    try:
        config = init_web_config()
        # Return safe config info (key presence only, never key values)
        safe_config = {
            'ai_provider': config.get('ai_provider'),
            'ai_providers': [
                {
                    'name': provider,
                    'default_model': get_default_model(provider),
                    'key_env': PROVIDER_KEY_ENV[provider],
                    'key_set': bool(os.getenv(PROVIDER_KEY_ENV[provider], '').strip()),
                }
                for provider in SUPPORTED_PROVIDERS
            ],
            'scan_level': config.get('scan_level'),
            'auto_fix_enabled': config.get('auto_fix', False),
            'scanners_available': ['semgrep', 'gitleaks', 'trivy', 'ai_scan']
        }
        return jsonify(safe_config)
    except Exception as e:
        logger.error(f"Config error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/scan', methods=['POST'])
def scan_repository():
    """
    Main scanning endpoint that calls existing CLI functions.

    Request body:
    {
        "repo_path": "/path/to/repository",
        "scan_level": "critical-high" | "all" (optional),
        "auto_fix": true | false (optional),
        "selected_tools": ["semgrep", "gitleaks", "trivy", "code_quality", "sbom"] (optional)
    }
    """
    try:
        # Parse request
        data = request.get_json()
        if not data or 'repo_path' not in data:
            return jsonify({'error': 'repo_path is required'}), 400

        repo_path = data['repo_path']
        scan_level = data.get('scan_level', 'critical-high')
        auto_fix = data.get('auto_fix', False)
        selected_tools = data.get('selected_tools', ['semgrep', 'gitleaks', 'trivy', 'code_quality', 'sbom'])
        requested_provider = str(data.get('ai_provider', '') or '').strip().lower()

        # Parse tool selection
        run_code_quality = 'code_quality' in selected_tools
        run_sbom = 'sbom' in selected_tools

        # Extract security scanners only
        scanners_to_run = [tool for tool in selected_tools if tool in ['semgrep', 'gitleaks', 'trivy', 'ai_scan']]

        # Ensure at least one scanner is selected
        if not scanners_to_run:
            return jsonify({'error': 'At least one security scanner must be selected'}), 400

        # AI provider selection: validate the choice and, when AI work is
        # requested, verify the key and run a one-token connection test so
        # misconfiguration fails fast with a clear message instead of half
        # way through a scan.
        from appsec_galaxy.scanners.ai_scanner import (
            PROVIDER_KEY_ENV, SUPPORTED_PROVIDERS, reset_ai_client_cache,
            test_ai_connection,
        )

        if requested_provider and requested_provider not in SUPPORTED_PROVIDERS:
            return jsonify({
                'error': f"ai_provider must be one of {', '.join(SUPPORTED_PROVIDERS)} "
                         f"(got '{requested_provider}')"
            }), 400

        # Validate repository path using existing function
        try:
            validated_path = validate_repo_path(repo_path)
        except (ValueError, PermissionError) as e:
            return jsonify({'error': f'Invalid repository path: {str(e)}'}), 400

        # Set environment variables for this scan
        original_scan_level = os.environ.get('APPSEC_SCAN_LEVEL')
        original_auto_fix = os.environ.get('APPSEC_AUTO_FIX')
        original_code_quality = os.environ.get('APPSEC_CODE_QUALITY')
        original_ai_provider = os.environ.get('AI_PROVIDER')

        logger.info(f"🔍 Web scan request - scan_level: {scan_level}, tools: {selected_tools}")
        os.environ['APPSEC_SCAN_LEVEL'] = scan_level
        os.environ['APPSEC_AUTO_FIX'] = str(auto_fix).lower()
        os.environ['APPSEC_CODE_QUALITY'] = 'true' if run_code_quality else 'false'
        if requested_provider:
            os.environ['AI_PROVIDER'] = requested_provider
            reset_ai_client_cache()
        logger.info(f"🔍 Web scan - configured APPSEC_SCAN_LEVEL={scan_level}, APPSEC_CODE_QUALITY={run_code_quality}")

        # AI scan requested: fail fast if the provider is not usable.
        ai_requested = 'ai_scan' in scanners_to_run or auto_fix
        if ai_requested:
            active_provider = (os.getenv('AI_PROVIDER', '') or 'openai').strip().lower() or 'openai'
            key_env = PROVIDER_KEY_ENV.get(active_provider)
            if key_env and not os.getenv(key_env, '').strip():
                _restore_env('AI_PROVIDER', original_ai_provider)
                reset_ai_client_cache()
                return jsonify({
                    'error': f"{key_env} is not set. Add it to your .env "
                             f"(see env.example) or choose a different AI provider."
                }), 400
            ok, message = test_ai_connection()
            if not ok:
                _restore_env('AI_PROVIDER', original_ai_provider)
                reset_ai_client_cache()
                return jsonify({'error': f'AI provider check failed: {message}'}), 400
            logger.info(f"✅ {message}")

        try:
            # Track usage for IP monitoring
            track_usage()

            # Initialize config
            init_web_config()

            # Set up output directory for repository
            output_path = get_output_path(str(validated_path), BASE_OUTPUT_DIR)

            # Clean up old scans (keep only most recent)
            cleanup_old_scans(output_path)

            # Set up directory structure
            output_dirs = setup_output_directories(output_path)
            output_dir = output_dirs['base']

            # Defense-in-depth: assert output_dir resolves under BASE_OUTPUT_DIR.
            # validate_repo_path already prevents path traversal in the input,
            # but AppSec Galaxy is a security tool: an explicit boundary check here
            # makes the safety property impossible to miss for future readers.
            _base = Path(BASE_OUTPUT_DIR).resolve()
            _resolved_out = Path(output_dir).resolve()
            if _base not in _resolved_out.parents and _resolved_out != _base:
                raise ValueError(
                    f"output_dir {_resolved_out} resolves outside BASE_OUTPUT_DIR {_base}"
                )

            # Track output dir for report serving
            global LAST_SCAN_OUTPUT_DIR
            LAST_SCAN_OUTPUT_DIR = output_dir

            # Run scanning logic
            print(f"🔍 Starting scan of {validated_path}")
            print(f"🔧 Running scanners: {', '.join(scanners_to_run)}")

            # Use existing scanning function with selected scanners
            all_findings = run_security_scans(str(validated_path), scanners_to_run, output_dir, scan_level)

            # Add cross-file analysis enhancement like CLI mode does
            enhanced_findings = all_findings
            try:
                from appsec_galaxy.enhanced_analyzer import enhance_findings_with_cross_file
                if all_findings:
                    print("🧠 Running cross-file enhancement analysis...")
                    enhanced_findings = asyncio.run(enhance_findings_with_cross_file(all_findings, str(validated_path)))
                    print(f"✅ Cross-file enhanced {len(enhanced_findings)} findings with context analysis")
            except ImportError:
                print("⚠️ Cross-file analysis integration not available")
            except Exception as e:
                print(f"⚠️ Cross-file enhancement failed: {e}")
                enhanced_findings = all_findings

            # Generate reports using existing functions
            html_report_path = None
            if enhanced_findings:
                # Separate security from code quality findings
                security_findings = [f for f in enhanced_findings if f.get('extra', {}).get('metadata', {}).get('category') != 'code_quality']
                code_quality_findings = [f for f in enhanced_findings if f.get('extra', {}).get('metadata', {}).get('category') == 'code_quality']

                summary_stats = {
                    'total_security': len(security_findings),
                    'total_code_quality': len(code_quality_findings),
                    'critical': len([f for f in security_findings if f.get('severity', '').lower() == 'critical']),
                    'high': len([f for f in security_findings if f.get('severity', '').lower() in ['high', 'error']]),
                    'sast': len([f for f in security_findings if f.get('tool') == 'semgrep']),
                    'secrets': len([f for f in security_findings if f.get('tool') == 'gitleaks']),
                    'deps': len([f for f in security_findings if f.get('tool') == 'trivy'])
                }

                # Build security findings section
                security_breakdown = f"""**Security Issues ({summary_stats['total_security']} total):**
• {summary_stats['critical']} critical vulnerabilities requiring immediate attention
• {summary_stats['high']} high-severity issues needing prompt remediation
• {summary_stats['sast']} code security issues (SAST)
• {summary_stats['secrets']} secrets detected in repository
• {summary_stats['deps']} vulnerable dependencies identified"""

                # Add code quality section if present
                code_quality_section = ""
                if summary_stats['total_code_quality'] > 0:
                    code_quality_section = f"""

**Code Quality Issues ({summary_stats['total_code_quality']} total):**
• Maintainability, complexity, and best practice violations
• Always shown regardless of security scan level"""

                ai_summary = f"""🛡️ Security Analysis Complete

**Risk Assessment:** {'🔴 High Risk' if summary_stats['critical'] > 0 else '🟡 Medium Risk' if summary_stats['high'] > 0 else '🟢 Low Risk'}

{security_breakdown}{code_quality_section}

**Recommended Actions:**
1. Prioritize critical vulnerabilities for immediate patching
2. Review and rotate any exposed secrets
3. Update vulnerable dependencies to latest secure versions
4. Implement security code review practices"""

                # Run dependency code-path analysis
                dep_health_data_web = None
                try:
                    from appsec_galaxy.dependency_analyzer import run_dependency_analysis
                    from appsec_galaxy.config import ENABLE_DEPENDENCY_ANALYSIS
                    if ENABLE_DEPENDENCY_ANALYSIS:
                        trivy_web = [f for f in enhanced_findings if f.get('tool') == 'trivy']
                        dep_health_data_web = run_dependency_analysis(str(validated_path), trivy_findings=trivy_web)
                        if dep_health_data_web and dep_health_data_web.analyzed_dependencies > 0:
                            print(f"📦 Analyzed {dep_health_data_web.analyzed_dependencies} dependencies")
                            dep_out = output_dir / "raw" / "dependency-health.json"
                            dep_out.parent.mkdir(parents=True, exist_ok=True)
                            import json as json_mod
                            # Filename is a constant; the parent dir was boundary-checked
                            # at output_dir construction (must resolve under BASE_OUTPUT_DIR).
                            # Semgrep taint-tracks the request->validated_path->output_dir
                            # chain but cannot see the runtime invariant.
                            with open(dep_out, 'w') as df:  # nosemgrep: python.flask.file.tainted-path-traversal-stdlib-flask.tainted-path-traversal-stdlib-flask
                                json_mod.dump(dep_health_data_web.to_dict(), df, indent=2)
                except ImportError:
                    pass
                except Exception as dep_err:
                    logger.warning(f"Dependency analysis failed: {dep_err}")

                html_report_path = generate_html_report(enhanced_findings, ai_summary, str(output_dir), str(validated_path), dep_health_data=dep_health_data_web)

                # Generate PR summary like CLI does
                try:
                    pr_summary_path = output_dir / "pr-findings.txt"
                    # Constant filename inside boundary-checked output_dir; see above.
                    with open(pr_summary_path, 'w') as f:  # nosemgrep: python.flask.file.tainted-path-traversal-stdlib-flask.tainted-path-traversal-stdlib-flask
                        f.write(f"Security Scan Results for {validated_path.name}\n")
                        f.write("=" * 50 + "\n\n")
                        f.write(ai_summary)
                        if len(enhanced_findings) > 0:
                            f.write("\n\nDetailed Findings:\n")
                            for i, finding in enumerate(enhanced_findings[:10], 1):  # Limit to top 10
                                f.write(f"{i}. {finding.get('extra', {}).get('message', 'Security issue')} ")
                                f.write(f"({finding.get('severity', 'unknown')} - {finding.get('tool', 'scanner')})\n")
                except Exception as e:
                    logger.warning(f"Could not generate PR summary: {e}")
            else:
                ai_summary = "🎉 Security scan completed successfully with no critical or high-severity issues found."
                html_report_path = generate_html_report([], ai_summary, str(output_dir), str(validated_path), dep_health_data=None)

            # Generate SBOM if user selected it
            if run_sbom:
                try:
                    from appsec_galaxy.sbom_generator import generate_repository_sbom
                    print("🔧 Generating SBOM...")
                    sbom_result = asyncio.run(generate_repository_sbom(str(validated_path), str(output_dir / "sbom")))
                    print("✅ SBOM generated successfully")
                    logger.info(f"SBOM generation results: {sbom_result}")
                except ImportError as e:
                    logger.error(f"SBOM generator module not found: {e}")
                except Exception as e:
                    logger.error(f"SBOM generation failed: {e}")
                    # Continue with scan even if SBOM fails

            # Handle auto-remediation non-interactively
            remediation_results = None
            if auto_fix and all_findings:
                # Get auto_fix_mode from request data (sent from frontend form)
                auto_fix_mode = data.get('auto_fix_mode', '3')  # Default to both if not specified

                # Set environment variables for non-interactive mode
                os.environ['APPSEC_WEB_MODE'] = 'true'
                os.environ['APPSEC_AUTO_FIX_MODE'] = str(auto_fix_mode)
                try:
                    print("🔧 Starting auto-remediation...")
                    remediation_results = handle_auto_remediation(str(validated_path), all_findings)
                    if remediation_results.get("success"):
                        print("✅ Auto-remediation completed")
                    else:
                        print(f"⚠️ Auto-remediation had issues: {remediation_results.get('message', 'Unknown error')}")
                except Exception as e:
                    logger.error(f"Auto-remediation failed: {e}")
                    remediation_results = {"success": False, "message": f"Auto-remediation failed: {str(e)}"}
                    print(f"❌ Auto-remediation failed: {e}")
                finally:
                    # Clean up environment variables
                    if 'APPSEC_WEB_MODE' in os.environ:
                        del os.environ['APPSEC_WEB_MODE']
                    if 'APPSEC_AUTO_FIX_MODE' in os.environ:
                        del os.environ['APPSEC_AUTO_FIX_MODE']

            # Prepare response with unique scan identifier
            import time
            scan_id = f"{Path(validated_path).name}_{int(time.time())}"

            response = {
                'success': True,
                'scan_id': scan_id,  # Add unique scan ID for cache-busting
                'scan_timestamp': int(time.time()),  # Add timestamp
                'scan_summary': {
                    'total_findings': len(all_findings),
                    'critical_findings': len([f for f in all_findings if f.get('severity') == 'critical']),
                    'high_findings': len([f for f in all_findings if f.get('severity') == 'high']),
                    'repository_path': str(validated_path),
                    'repository_name': Path(validated_path).name,  # Add repo name
                    'scan_level': scan_level,
                    'auto_fix_enabled': auto_fix
                },
                'findings': all_findings,
                'html_report_available': html_report_path is not None,
                'remediation_applied': remediation_results is not None
            }

            if remediation_results:
                response['remediation_summary'] = remediation_results

            logger.info(f"✅ Web scan completed: {len(all_findings)} findings")
            return jsonify(response)

        finally:
            # Restore original environment variables
            _restore_env('APPSEC_SCAN_LEVEL', original_scan_level)
            _restore_env('APPSEC_AUTO_FIX', original_auto_fix)
            _restore_env('APPSEC_CODE_QUALITY', original_code_quality)
            if requested_provider:
                _restore_env('AI_PROVIDER', original_ai_provider)
                reset_ai_client_cache()

    except Exception as e:
        logger.error(f"Scan error: {e}")
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500

@app.route('/report', methods=['GET'])
def get_html_report():
    """Serve the generated HTML report with aggressive cache-busting."""
    try:
        global LAST_SCAN_OUTPUT_DIR

        if LAST_SCAN_OUTPUT_DIR is None:
            return jsonify({'error': 'No scan has been run yet. Please run a scan first.'}), 404

        report_path = Path(LAST_SCAN_OUTPUT_DIR) / "report.html"
        if not report_path.exists():
            return jsonify({'error': 'No report available. Run a scan first.'}), 404

        # Read file content instead of sending file directly to bypass browser cache
        with open(report_path, encoding='utf-8') as f:
            content = f.read()

        from flask import Response
        response = Response(content, mimetype='text/html')

        # Aggressive cache-busting headers
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # Add ETag based on file modification time to force refresh
        import os
        mtime = os.path.getmtime(report_path)
        response.headers['ETag'] = f'"{mtime}"'
        response.headers['Last-Modified'] = report_path.stat().st_mtime

        return response

    except Exception as e:
        logger.error(f"Report error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/reports/<filename>', methods=['GET'])
def get_report_file(filename):
    """Serve specific report files (JSON, SBOM, etc.)."""
    try:
        global LAST_SCAN_OUTPUT_DIR

        if LAST_SCAN_OUTPUT_DIR is None:
            return jsonify({'error': 'No scan has been run yet. Please run a scan first.'}), 404

        # Security: Only allow specific file types
        allowed_files = {
            'semgrep.json', 'gitleaks.json', 'trivy-sca.json', 'ai_scan.json',
            'sbom.cyclonedx.json', 'sbom.spdx.json', 'pr-findings.txt',
            'dependency-health.json'
        }

        if filename not in allowed_files:
            return jsonify({'error': 'File not allowed'}), 403

        output_dir = Path(LAST_SCAN_OUTPUT_DIR)

        if filename.endswith('.json') and not filename.startswith('sbom'):
            file_path = output_dir / "raw" / filename
        elif filename.startswith('sbom'):
            file_path = output_dir / "sbom" / filename
        else:
            file_path = output_dir / filename

        if not file_path.exists():
            return jsonify({'error': 'File not found'}), 404

        response = send_file(file_path, as_attachment=True)
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    except Exception as e:
        logger.error(f"File error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/dependency-health', methods=['GET'])
def get_dependency_health():
    """Return dependency health analysis as JSON."""
    try:
        global LAST_SCAN_OUTPUT_DIR
        if LAST_SCAN_OUTPUT_DIR is None:
            return jsonify({'error': 'No scan has been run yet'}), 404

        dep_path = Path(LAST_SCAN_OUTPUT_DIR) / "raw" / "dependency-health.json"
        if not dep_path.exists():
            return jsonify({'error': 'No dependency analysis data. Run a scan first.'}), 404

        with open(dep_path) as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        logger.error(f"Dependency health error: {e}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'API endpoint not found'}), 404

@app.route('/', methods=['GET'])
def index():
    """Main web interface for the scanner."""
    # Get repository info to display server-side
    logger.info("Loading index page, getting repository info...")
    try:
        current_dir_info = get_current_directory_info()
        logger.info(f"Repository info: {current_dir_info}")
        return render_template('index.html',
                             repo_path=current_dir_info['path'],
                             repo_display_name=current_dir_info['display_name'])
    except Exception as e:
        logger.error(f"Error getting repo info for template: {e}")
        logger.error(f"Exception details: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return render_template('index.html',
                             repo_path='/app/scan',
                             repo_display_name='mounted-repository')

def get_current_directory_info():
    """Helper function to get current directory info."""
    # In Docker container, use the standard mounted scan directory
    if os.path.exists('/app/scan'):
        # Get the actual repository name from the mounted directory
        try:
            # Try to get git repository name
            import subprocess
            result = subprocess.run(['git', 'rev-parse', '--show-toplevel'],
                                  cwd='/app/scan', capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                repo_name = os.path.basename(result.stdout.strip())
            else:
                # Fallback to directory name
                repo_name = "mounted-repository"
                # Try to read some files to get a better name
                scan_dir = Path('/app/scan')
                if (scan_dir / 'package.json').exists():
                    import json
                    try:
                        with open(scan_dir / 'package.json') as f:
                            pkg = json.load(f)
                            repo_name = pkg.get('name', repo_name)
                            logger.info(f"Found package.json with name: {repo_name}")
                    except Exception as e:
                        logger.error(f"Error reading package.json: {e}")
                else:
                    logger.info(f"package.json not found at {scan_dir / 'package.json'}")
                    # List what files ARE there for debugging
                    try:
                        files = list(scan_dir.glob('*'))[:10]  # First 10 files
                        logger.info(f"Files in scan dir: {[f.name for f in files]}")
                    except Exception as e:
                        logger.error(f"Error listing scan dir: {e}")

                    # Try other file types
                    if (scan_dir / 'pyproject.toml').exists() or (scan_dir / 'setup.py').exists():
                        repo_name = scan_dir.name if scan_dir.name != 'scan' else repo_name
        except Exception:
            repo_name = "mounted-repository"

        return {
            'path': '/app/scan',
            'display_name': repo_name
        }
    else:
        # Fallback to actual current directory for local development
        current_dir = Path(os.getcwd())
        repo_path = current_dir
        repo_name = current_dir.name

        try:
            result = subprocess.run(
                ['git', 'rev-parse', '--show-toplevel'],
                cwd=current_dir,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                repo_path = Path(result.stdout.strip())
                repo_name = repo_path.name
        except Exception:
            pass

        return {
            'path': str(repo_path),
            'display_name': repo_name
        }

@app.route('/current-directory', methods=['GET'])
def get_current_directory():
    """Get the current working directory."""
    try:
        # In Docker container, use the standard mounted scan directory
        if os.path.exists('/app/scan'):
            # Get the actual repository name from the mounted directory
            try:
                # Try package.json FIRST (more reliable than git for mounted repos)
                scan_dir = Path('/app/scan')
                repo_name = "mounted-repository"

                if (scan_dir / 'package.json').exists():
                    import json
                    with open(scan_dir / 'package.json') as f:
                        pkg = json.load(f)
                        repo_name = pkg.get('name', repo_name)
                elif (scan_dir / 'pyproject.toml').exists() or (scan_dir / 'setup.py').exists():
                    repo_name = scan_dir.name if scan_dir.name != 'scan' else repo_name
            except Exception:
                repo_name = "mounted-repository"

            return jsonify({
                'path': '/app/scan',
                'display_name': repo_name
            })
        else:
            current_dir = Path(os.getcwd())
            repo_path = current_dir
            repo_name = current_dir.name

            try:
                result = subprocess.run(
                    ['git', 'rev-parse', '--show-toplevel'],
                    cwd=current_dir,
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    repo_path = Path(result.stdout.strip())
                    repo_name = repo_path.name
            except Exception:
                pass

            return jsonify({
                'path': str(repo_path),
                'display_name': repo_name
            })
    except Exception as e:
        logger.error(f"Error getting current directory: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/discover-repos', methods=['GET'])
def discover_repositories():
    """Discover repositories in common locations."""
    if not _directory_browsing_enabled():
        return jsonify({'error': 'Repository discovery disabled by server policy'}), 403

    try:
        repositories = []

        # Default scope: ~/repos only. Broad defaults (Documents, Desktop,
        # Downloads) surfaced far too much noise; anything beyond ~/repos
        # is opt-in via REPO_SEARCH_PATHS.
        home_dir = Path.home()
        search_paths = [home_dir / "repos"]

        # Add custom search paths from env
        custom_paths = os.getenv('REPO_SEARCH_PATHS', '')
        if custom_paths:
            for p in custom_paths.split(','):
                p = p.strip()
                if p:
                    search_paths.append(Path(p))

        for search_path in search_paths:
            if search_path.exists() and search_path.is_dir():
                try:
                    for item in search_path.iterdir():
                        if item.is_dir() and not item.name.startswith('.'):
                            repo_info = _classify_directory(item)
                            repositories.append(repo_info)
                            if len(repositories) >= 50:
                                break
                except (PermissionError, OSError):
                    continue
            if len(repositories) >= 50:
                break

        repositories.sort(key=lambda x: x['name'].lower())
        return jsonify({'repositories': repositories})

    except Exception as e:
        logger.error(f"Error discovering repositories: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/browse-dir', methods=['GET'])
def browse_directory():
    """Browse into a directory to find repositories. Supports drill-down navigation."""
    if not _directory_browsing_enabled():
        return jsonify({'error': 'Directory browsing disabled by server policy'}), 403

    dir_path = request.args.get('path', '')
    if not dir_path:
        return jsonify({'error': 'path parameter required'}), 400

    try:
        validated_path = validate_repo_path(dir_path)
    except (ValueError, PermissionError) as e:
        return jsonify({'error': str(e)}), 400

    try:
        items = []
        target = Path(validated_path)
        if not target.is_dir():
            return jsonify({'error': 'Not a directory'}), 400

        for item in sorted(target.iterdir(), key=lambda x: x.name.lower()):
            if not item.is_dir() or item.name.startswith('.'):
                continue
            items.append(_classify_directory(item))
            if len(items) >= 50:
                break

        return jsonify({
            'current_path': str(target),
            'parent_path': str(target.parent) if target.parent != target else None,
            'items': items
        })
    except (PermissionError, OSError) as e:
        return jsonify({'error': f'Cannot read directory: {e}'}), 403


def _classify_directory(item: Path) -> dict:
    """Classify a directory as git repo, project type, or plain directory."""
    repo_info = {
        'name': item.name,
        'path': str(item),
        'type': 'directory'
    }
    if (item / '.git').exists():
        repo_info['type'] = 'git'
    elif (item / 'package.json').exists():
        repo_info['type'] = 'nodejs'
    elif (item / 'requirements.txt').exists() or (item / 'pyproject.toml').exists():
        repo_info['type'] = 'python'
    return repo_info

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    import datetime

    # Track web interface startup
    track_usage()

    # Get port from environment variable (for Docker/App Runner compatibility)
    port = int(os.environ.get('PORT', 8000))
    host = os.environ.get('HOST', '0.0.0.0')

    print("="*80)
    print("🔒 AppSec Galaxy Web Interface  ·  Application security, mapped.")
    print("="*80)
    print(f"🚀 Starting Web API at {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
    print(f"🌐 Listening on http://{host}:{port}")
    print("="*80)
    print()
    print("📖 API Documentation:")
    print("  GET  /health          - Health check")
    print("  GET  /config          - Get scanner configuration")
    print("  POST /scan            - Run security scan")
    print("  GET  /report          - View HTML report")
    print("  GET  /reports/<file>  - Download specific report files")
    print()
    print("💡 Example scan request:")
    print(f'  curl -X POST http://localhost:{port}/scan \\')
    print('       -H "Content-Type: application/json" \\')
    print('       -d \'{"repo_path": "/path/to/repo", "scan_level": "critical-high"}\'')
    print()
    print("📊 Usage analytics enabled for IP monitoring while repository is public")
    if host == '0.0.0.0' and not os.environ.get("APPSEC_WEB_API_KEY"):
        print("⚠️ WARNING: APPSEC_WEB_API_KEY is not set while binding to 0.0.0.0")
        print("   Sensitive API routes may be accessible to anyone with network access.")
    print("="*80)

    # Run Flask development server
    app.run(
        host=host,  # Accept connections from configured interface
        port=port,
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    )
