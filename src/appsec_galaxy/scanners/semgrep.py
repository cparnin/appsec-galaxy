import subprocess
import json
from pathlib import Path
import os
import sys
import shlex

# Import configuration constants
from appsec_galaxy.config import format_subprocess_error, SCAN_EXCLUDE_PATTERNS
from appsec_galaxy.finding import Finding
from .validation import validate_repo_path
from appsec_galaxy.logging_config import get_logger

logger = get_logger(__name__)

def _categorize_finding(check_id: str) -> str:
    """
    Categorize a Semgrep finding as 'security' only.

    Note: Semgrep is ONLY used for security analysis. Code quality is handled
    by language-specific linters (Pylint, ESLint, Clippy, RuboCop, etc.)

    Args:
        check_id: Semgrep check ID (e.g., 'javascript.lang.security.audit.sqli')

    Returns:
        'security' (always - code quality categorization disabled)
    """
    # Semgrep is exclusively for security analysis
    # Language-specific linters handle code quality
    return 'security'

def run_semgrep(repo_path: str, output_dir: str | None = None, scan_level: str | None = None) -> list:
    """
    Run Semgrep SAST scanner on the given repository path.
    Returns a list of findings in standardized format.

    Args:
        repo_path: Path to repository to scan
        output_dir: Directory for output files (defaults to ../outputs/raw)
        scan_level: Scan level ('critical-high' or 'all'), overrides APPSEC_SCAN_LEVEL env var
    """
    try:
        # Convert to Path objects for proper handling
        if output_dir is None:
            from appsec_galaxy.config import BASE_OUTPUT_DIR
            output_path = Path(BASE_OUTPUT_DIR) / "raw"
        else:
            output_path = Path(output_dir)

        output_path.mkdir(parents=True, exist_ok=True)
        semgrep_home = (output_path.parent / '.semgrep')
        semgrep_home.mkdir(parents=True, exist_ok=True)
        output_file = output_path / "semgrep.json"

        # Validate and sanitize repo path
        repo_path_obj = validate_repo_path(repo_path)
        if not repo_path_obj:
            logger.error(f"Repository path validation failed: {repo_path}")
            return []

        logger.debug(f"Starting Semgrep scan of {repo_path_obj}")
        logger.debug(f"Output file: {output_file}")

        # Debug: Check if critical files exist
        critical_files = ['routes/index.js', 'app.js', 'Dockerfile']
        for file in critical_files:
            file_path = repo_path_obj / file
            exists = file_path.exists()
            size = file_path.stat().st_size if exists else 0
            logger.debug(f"Critical file check: {file} exists={exists} size={size}")

        # Use auto config for consistent rule loading across all environments
        # This downloads the latest available rules and ensures CI/CD vs CLI consistency
        semgrep_exe = Path(sys.executable).with_name('semgrep')
        if semgrep_exe.exists():
            cmd = [str(semgrep_exe)]
        else:
            cmd = ["semgrep"]

        cmd.extend([
            "--config", "auto",  # Security rules
            "--metrics=off",  # No scan telemetry to the Semgrep registry (private/client code)
            "--json",
            "--output", str(output_file)
        ])

        # Add code quality rules if enabled
        # Note: p/code-smells and p/maintainability were deprecated by Semgrep
        # Code quality patterns are now part of the standard security rules via --config auto
        from appsec_galaxy.config import ENABLE_CODE_QUALITY
        if ENABLE_CODE_QUALITY:
            logger.info("📊 Code quality scanning enabled (included in --config auto)")
            # The --config auto already includes best-practice and correctness rules
            # No need to add separate rulesets

        # Add exclusion patterns
        for pattern in SCAN_EXCLUDE_PATTERNS:
            cmd.extend(["--exclude", pattern])

        cmd.append(str(repo_path_obj))

        logger.debug(f"Semgrep command: {' '.join(shlex.quote(arg) for arg in cmd)}")

        # Use subprocess.run with shell=False for security
        # Ensure Semgrep can validate TLS even if system trust stores aren't configured
        env = os.environ.copy()
        ssl_cert_file = env.get('SSL_CERT_FILE')
        if not ssl_cert_file or not Path(ssl_cert_file).exists():
            try:
                import certifi
                env['SSL_CERT_FILE'] = certifi.where()
            except Exception:
                logger.debug("Could not set SSL_CERT_FILE via certifi")
        if env.get('SSL_CERT_FILE'):
            env.setdefault('REQUESTS_CA_BUNDLE', env['SSL_CERT_FILE'])
            env.setdefault('CURL_CA_BUNDLE', env['SSL_CERT_FILE'])
            cert_dir = str(Path(env['SSL_CERT_FILE']).parent)
            env.setdefault('SSL_CERT_DIR', cert_dir)
        env.setdefault('SEMGREP_FORCE_NO_LOG', '1')
        env.setdefault('SEMGREP_APP_HOME', str(semgrep_home))
        env.setdefault('HOME', str(semgrep_home))

        # Ensure the virtualenv's bin directory is on PATH so the semgrep CLI resolves
        try:
            venv_bin = str(Path(sys.executable).parent)
        except Exception:
            venv_bin = None
        if venv_bin and venv_bin not in env.get('PATH', ''):
            env['PATH'] = f"{venv_bin}:{env.get('PATH', '')}"

        logger.debug(f"Semgrep SSL_CERT_FILE={env.get('SSL_CERT_FILE')} REQUESTS_CA_BUNDLE={env.get('REQUESTS_CA_BUNDLE')} SSL_CERT_DIR={env.get('SSL_CERT_DIR')}")

        # Delete old output file BEFORE running to prevent loading stale results
        if output_file.exists():
            output_file.unlink()
            logger.debug(f"Deleted old semgrep output file: {output_file}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, shell=False, env=env)

        logger.debug(f"Semgrep completed with return code: {result.returncode}")
        if result.stderr:
            logger.debug(f"Semgrep stderr: {result.stderr[:200]}")
        if result.returncode not in (0, 1, 2):
            error_details = format_subprocess_error('semgrep', result.returncode, result.stderr, result.stdout)
            logger.error(error_details)
            # Don't continue with stale results - fail clearly
            logger.error("Semgrep failed - not loading old cached results")
            return []
        if result.returncode == 2:
            # Exit code 2 means semgrep hit internal errors (e.g. Pro-only rules on the
            # free engine).  It still writes valid findings to the output file - let the
            # file-existence check below decide whether to continue.
            logger.warning(f"Semgrep exited with code 2 (internal errors); output file may still contain valid findings. stderr: {result.stderr[:300]}")

        if not output_file.exists():
            logger.error("Semgrep did not produce an output file; returning no findings")
            return []

        # Parse and return findings from the JSON output
        with open(output_file) as f:
            all_results = json.load(f).get("results", [])

        logger.debug(f"Semgrep found {len(all_results)} total findings")

        # Filter based on scan level - Semgrep uses: CRITICAL, ERROR, WARNING, INFO
        # CRITICAL = Critical, ERROR = High, WARNING = Medium, INFO = Low
        # Use parameter if provided, otherwise fall back to environment variable
        if scan_level is None:
            scan_level = os.getenv('APPSEC_SCAN_LEVEL', 'critical-high')
            logger.info(f"🔍 Semgrep filtering - Scan Level: {scan_level} (from APPSEC_SCAN_LEVEL env var)")
        else:
            logger.info(f"🔍 Semgrep filtering - Scan Level: {scan_level} (from parameter)")
        logger.info(f"📊 Total findings before filtering: {len(all_results)}")

        # Debug: Show severity breakdown before filtering
        severity_counts: dict[str, int] = {}
        for finding in all_results:
            severity = finding.get('extra', {}).get('severity') or finding.get('severity', '')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        logger.info(f"📈 Severity breakdown: {severity_counts}")

        results = []
        for finding in all_results:
            severity = finding.get('extra', {}).get('severity') or finding.get('severity', '')
            severity_lower = severity.lower()

            # Map Semgrep severities to standard levels for filtering
            if severity_lower == 'critical':
                normalized_severity = 'critical'
            elif severity_lower == 'error':
                normalized_severity = 'high'  # ERROR = High severity
            elif severity_lower == 'warning':
                normalized_severity = 'medium'  # WARNING = Medium severity
            elif severity_lower == 'info':
                normalized_severity = 'low'  # INFO = Low severity
            else:
                logger.debug(f"Skipping finding with unknown severity: {severity}")
                continue  # Skip unknown severities

            # Categorize the finding first (needed for filtering logic)
            category = _categorize_finding(finding.get('check_id', ''))

            # Filter based on scan level AND category
            # Security findings are filtered by scan level
            # Code quality categorization is now disabled for Semgrep (returns 'security' only)
            include_finding = False

            if category == 'code_quality':
                # This branch is now unreachable since _categorize_finding always returns 'security'
                # Kept for backwards compatibility if categorization is re-enabled
                include_finding = True
                logger.debug(f"✅ Including code_quality finding: {finding.get('check_id', 'unknown')} [{normalized_severity}]")
            elif scan_level == 'critical-high' and normalized_severity in ['critical', 'high']:
                # Include critical/high security findings when scan_level is critical-high
                include_finding = True
                logger.debug(f"✅ Including {normalized_severity} security finding: {finding.get('check_id', 'unknown')}")
            elif scan_level == 'all':
                # Include all security findings when scan_level is all
                include_finding = True
                logger.debug(f"✅ Including {normalized_severity} security finding: {finding.get('check_id', 'unknown')}")
            else:
                logger.debug(f"❌ Filtering out {normalized_severity} security finding: {finding.get('check_id', 'unknown')} (scan_level={scan_level})")

            if include_finding:
                results.append(Finding.from_semgrep(finding, normalized_severity, category).to_dict())

        # Final results summary
        final_severity_counts: dict[str, int] = {}
        for finding in results:
            severity = finding.get('severity', 'unknown')
            final_severity_counts[severity] = final_severity_counts.get(severity, 0) + 1

        logger.info(f"✅ Semgrep final results: {len(results)} findings after {scan_level} filtering")
        logger.info(f"📊 Final severity breakdown: {final_severity_counts}")
        logger.info(f"🔍 Filtered out {len(all_results) - len(results)} findings")

        return results

    except subprocess.TimeoutExpired:
        timeout_msg = format_subprocess_error('semgrep', 124, "Process timed out after 5 minutes")
        logger.error(timeout_msg)
        return []
    except FileNotFoundError:
        not_found_msg = format_subprocess_error('semgrep', 127, "Semgrep command not found in PATH")
        logger.error(not_found_msg)
        return []
    except Exception as e:
        generic_msg = format_subprocess_error('semgrep', 1, str(e))
        logger.error(generic_msg)
        return []
