from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


# Phrases that mean "the AI could not actually assess the code" rather than
# "I confirmed there is no sanitization." Surfacing these as status=NONE
# misrepresents data-availability noise as real findings.
_AI_CANNOT_ASSESS_PHRASES = (
    'not visible',
    'cannot assess',
    'cannot determine',
    'could not assess',
    'could not determine',
    'not shown',
    'insufficient context',
    'file ends at',
)


def _extract_sanitization_finding(finding: dict[str, Any], repo_path: str | None) -> dict[str, Any] | None:
    """Project a raw finding into a sanitization-display dict, or None if it
    should be filtered out.

    Two responsibilities:
      1. Drop "none" entries whose details just mean the AI couldn't see
         the code. These are not real findings.
      2. Convert absolute file paths to repo-relative so the report does
         not leak the scan host's filesystem layout.
    """
    status = finding.get('ai_sanitization_status')
    if not status:
        return None

    details = finding.get('ai_sanitization_details', '') or ''
    if status == 'none':
        low = details.lower()
        if any(phrase in low for phrase in _AI_CANNOT_ASSESS_PHRASES):
            return None

    file_path = finding.get('path', '') or ''
    if repo_path and file_path.startswith(repo_path):
        file_path = file_path[len(repo_path):].lstrip('/').lstrip('\\')

    return {
        'file': file_path,
        'line': finding.get('start', {}).get('line', 0),
        'status': status,
        'details': details,
        'false_positive_likelihood': finding.get('ai_false_positive_likelihood', 0),
    }

def generate_html_report(findings: list[dict[str, Any]], ai_summary: str, output_dir: str, repo_path: str | None = None, detected_languages: set | None = None, dep_health_data=None) -> str:
    """
    Generate an HTML report from the scanner findings.

    Args:
        findings (list): List of all findings from scanners
        ai_summary (str): AI-generated executive summary
        output_dir (str): Directory to write the HTML report
        repo_path (str): Path to the scanned repository
        detected_languages (set): Set of detected programming languages
    """

    def sort_by_severity(finding):
        """Sort findings by severity priority: Critical > High > Error"""
        severity = (finding.get('extra', {}).get('severity') or
                   finding.get('severity', '')).lower()

        # Map severity to sort order (lower number = higher priority)
        # Only critical, high, and error since we filter out warning/medium
        severity_order = {
            'critical': 1,
            'error': 2,    # Semgrep uses ERROR for high severity
            'high': 2,
            '': 6          # Unknown severity goes last
        }
        return severity_order.get(severity, 6)

    try:
        # Convert output_dir to Path object if it's a string
        output_path = Path(output_dir)

        # Group findings by tool
        results: dict[str, list[dict[str, Any]]] = {}
        for finding in findings:
            tool = finding.get('tool', 'unknown')
            if tool not in results:
                results[tool] = []
            results[tool].append(finding)

        # Load Jinja2 template.
        # autoescape on: AppSec Galaxy scans hostile code, so findings carry strings
        # (file paths, scanner messages, code snippets, CWE descriptions)
        # that may contain HTML-active characters. Without autoescape, a
        # repo containing a file named e.g. `<script>alert(1)</script>.py`
        # would inject script into the report. The AI executive summary
        # is pre-rendered HTML and is marked `| safe` in the template;
        # _markdown_to_html escapes user content itself before adding tags.
        template_dir = Path(__file__).parent / "templates"
        # False positive: the rule flags any Environment() call. We pass
        # autoescape=select_autoescape([...]) which is the canonical
        # Jinja2 XSS defense for HTML output. See TestMarkdownToHtml and
        # the comment block above for the safety reasoning.
        env = Environment(  # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'htm']),
        )

        # `relpath` filter: render any path as repo-relative. Customer
        # reports must not leak the scan host's filesystem layout
        # (e.g. /Users/cparnin/repos/...). The filter is intentionally
        # forgiving: paths outside the repo are returned unchanged
        # (better than mangling something we don't recognize).
        _repo_prefix = (repo_path or '').rstrip('/').rstrip('\\')
        def _to_relpath(value):
            if not value or not isinstance(value, str):
                return value
            if _repo_prefix and value.startswith(_repo_prefix):
                return value[len(_repo_prefix):].lstrip('/').lstrip('\\') or value
            return value
        env.filters['relpath'] = _to_relpath

        template = env.get_template("report.html")

        # Sort findings by severity for each tool
        sorted_results = {}
        for tool, tool_findings in results.items():
            if tool_findings:
                sorted_results[tool] = sorted(tool_findings, key=sort_by_severity)
            else:
                sorted_results[tool] = tool_findings

        # Count total findings and severity breakdown
        total_findings = len(findings)
        critical_count = 0
        high_count = 0
        cross_file_enhanced_count = 0
        attack_chains_count = 0

        # Extract cross-file analysis data for enhanced reporting with smart limits
        cross_file_context_data: dict[str, Any] = {
            'frameworks_detected': set(),
            'languages_detected': set(),
            'attack_chains': [],
            'business_impacts': [],
            'cross_file_vulnerabilities': []
        }

        # Adaptive limits based on total findings (prevent wall of text)
        is_large_scan = total_findings > 20  # Likely intentionally vulnerable repo
        max_attack_chains = 3 if is_large_scan else 5
        max_business_impacts = 5 if is_large_scan else 8  # Expanded from 2->5, 3->8

        for finding in findings:
            severity = (finding.get('extra', {}).get('severity') or
                       finding.get('severity', '')).lower()
            if severity == 'critical':
                critical_count += 1
            elif severity in ['high', 'error']:
                high_count += 1

            # Extract cross-file analysis data from findings
            if finding.get('cross_file_analysis'):
                cross_file_enhanced_count += 1

                # Extract cross-file analysis with limits
                cross_file = finding.get('cross_file_analysis', {})
                if cross_file.get('potential_attack_chains') and len(cross_file_context_data['attack_chains']) < max_attack_chains * 2:
                    for chain in cross_file['potential_attack_chains']:
                        if len(cross_file_context_data['attack_chains']) >= max_attack_chains * 2:
                            break
                        cross_file_context_data['attack_chains'].append({
                            'type': chain.get('chain_type', 'Unknown'),
                            'severity': chain.get('severity', 'Unknown'),
                            'entry_point': chain.get('entry_point', 'Unknown'),
                            'sink': chain.get('sink', 'Unknown'),
                            'description': chain.get('description', ''),
                            'files_involved': len(chain.get('attack_path', [])),
                            'priority': 1 if chain.get('severity', '').lower() in ['critical', 'high'] else 2
                        })
                        attack_chains_count += 1

                # Extract business impact data with limits
                business_impact = finding.get('business_impact', {})
                if business_impact.get('business_justification') and len(cross_file_context_data['business_impacts']) < max_business_impacts * 2:
                    cross_file_context_data['business_impacts'].append({
                        'file': finding.get('path', ''),
                        'vulnerability': finding.get('check_id', ''),
                        'impact': business_impact.get('business_justification', ''),
                        'financial_risk': business_impact.get('financial_risk', 'Unknown'),
                        'priority': 1 if business_impact.get('financial_risk', '').lower() == 'high' else 2
                    })

            # Extract technology stack info from cross-file analysis summaries
            cross_file_summary = finding.get('cross_file_summary', '')
            if 'Tech:' in cross_file_summary:
                tech_part = cross_file_summary.split('Tech:')[-1].strip()
                if tech_part:
                    frameworks = [fw.strip() for fw in tech_part.split(',')]
                    cross_file_context_data['frameworks_detected'].update(frameworks)

        # Sort and limit data for template
        cross_file_context_data['frameworks_detected'] = list(cross_file_context_data['frameworks_detected'])[:8]  # Max 8 frameworks
        cross_file_context_data['languages_detected'] = list(cross_file_context_data['languages_detected'])

        # Sort attack chains by priority (critical/high first) and limit
        cross_file_context_data['attack_chains'] = sorted(cross_file_context_data['attack_chains'],
                                                  key=lambda x: (x.get('priority', 2), x.get('type', '')))
        cross_file_context_data['attack_chains'] = cross_file_context_data['attack_chains'][:max_attack_chains]

        # Sort business impacts by priority and limit
        cross_file_context_data['business_impacts'] = sorted(cross_file_context_data['business_impacts'],
                                                     key=lambda x: (x.get('priority', 2), x.get('file', '')))
        cross_file_context_data['business_impacts'] = cross_file_context_data['business_impacts'][:max_business_impacts]

        # Extract AI cross-file insights (Phase 2: LLM-powered analysis)
        ai_cross_file_data: dict[str, Any] = {
            'enabled': False,
            'compound_risk_groups': [],
            'validated_chains': [],
            'sanitization_findings': [],
        }

        for finding in findings:
            # Compound risk correlations
            if finding.get('ai_compound_risk'):
                ai_cross_file_data['enabled'] = True
                group_desc = finding['ai_compound_risk']
                # Avoid duplicate group entries
                existing = [g['risk'] for g in ai_cross_file_data['compound_risk_groups']]
                if group_desc not in existing:
                    ai_cross_file_data['compound_risk_groups'].append({
                        'risk': group_desc,
                        'severity': finding.get('ai_compound_severity', 'high'),
                        'narrative': finding.get('ai_attack_narrative', ''),
                    })

            # Sanitization validation results (filtered + relativized)
            sanitization_entry = _extract_sanitization_finding(finding, repo_path)
            if sanitization_entry:
                ai_cross_file_data['enabled'] = True
                ai_cross_file_data['sanitization_findings'].append(sanitization_entry)

        # Extract AI-validated attack chains from cross_file_context_data
        for chain in cross_file_context_data.get('attack_chains', []):
            if chain.get('ai_validated') is not None:
                ai_cross_file_data['enabled'] = True
                ai_cross_file_data['validated_chains'].append({
                    'type': chain.get('type', ''),
                    'exploitable': chain.get('ai_validated', None),
                    'explanation': chain.get('ai_exploitability', ''),
                    'confidence': chain.get('ai_confidence', 0),
                })

        # Limit for template readability
        ai_cross_file_data['compound_risk_groups'] = ai_cross_file_data['compound_risk_groups'][:5]
        ai_cross_file_data['sanitization_findings'] = ai_cross_file_data['sanitization_findings'][:8]

        # Generate AI executive summary if enabled (replaces static template)
        try:
            from appsec_galaxy.reporting.ai_summary import generate_ai_executive_summary
            # Merge cross-file + AI cross-file data for the summary prompt
            summary_context = {
                'attack_chains': cross_file_context_data.get('attack_chains', []),
                'compound_risk_groups': ai_cross_file_data.get('compound_risk_groups', []),
            }
            ai_summary = generate_ai_executive_summary(
                findings=findings,
                repo_path=repo_path or "",
                cross_file_data=summary_context,
                static_summary=ai_summary,
            )
        except Exception as e:
            logger.warning(f"AI executive summary failed, using static: {e}")

        # Add metadata for template
        cross_file_context_data['is_large_scan'] = is_large_scan
        cross_file_context_data['max_attack_chains'] = max_attack_chains
        cross_file_context_data['max_business_impacts'] = max_business_impacts

        # Look for SBOM data in outputs directory
        sbom_data = {}
        sbom_files = ['sbom.cyclonedx.json', 'sbom.spdx.json']
        output_path_obj = Path(output_dir)

        logger.debug(f"Looking for SBOM files in: {output_path_obj / 'sbom'}")

        for sbom_file in sbom_files:
            sbom_path = output_path_obj / 'sbom' / sbom_file
            logger.debug(f"Checking SBOM file: {sbom_path} (exists: {sbom_path.exists()})")
            if sbom_path.exists():
                try:
                    import json
                    with open(sbom_path) as f:
                        sbom_content = json.load(f)
                        # Extract key information for display
                        if 'components' in sbom_content:  # CycloneDX format
                            sbom_data[sbom_file] = {
                                'format': 'CycloneDX',
                                'components': len(sbom_content.get('components', [])),
                                'dependencies': len(sbom_content.get('dependencies', [])),
                                'file': sbom_file
                            }
                            logger.debug(f"Added CycloneDX SBOM data: {len(sbom_content.get('components', []))} components")
                        elif 'packages' in sbom_content:  # SPDX format
                            sbom_data[sbom_file] = {
                                'format': 'SPDX',
                                'packages': len(sbom_content.get('packages', [])),
                                'relationships': len(sbom_content.get('relationships', [])),
                                'file': sbom_file
                            }
                            logger.debug(f"Added SPDX SBOM data: {len(sbom_content.get('packages', []))} packages")
                except Exception as e:
                    logger.error(f"Could not parse SBOM file {sbom_file}: {e}")

        logger.debug(f"Final SBOM data for template: {sbom_data}")

        # Render template with findings data
        # Add timestamp for when report was generated (Eastern Time)
        from zoneinfo import ZoneInfo
        eastern = ZoneInfo("America/New_York")
        scan_timestamp = datetime.now(eastern).strftime("%Y-%m-%d %H:%M:%S EST")

        # Prepare dependency health data for template
        dependency_health_template_data = None
        if dep_health_data and hasattr(dep_health_data, 'to_dict'):
            dep_dict = dep_health_data.to_dict()
            if dep_dict.get('analyzed_dependencies', 0) > 0:
                dependency_health_template_data = dep_dict
        elif isinstance(dep_health_data, dict) and dep_health_data.get('analyzed_dependencies', 0) > 0:
            dependency_health_template_data = dep_health_data

        # Load AI scan cost data if available
        ai_cost_data = None
        ai_scan_file = output_path_obj / 'raw' / 'ai_scan.json'
        if ai_scan_file.exists():
            try:
                import json
                with open(ai_scan_file) as f:
                    ai_scan_raw = json.load(f)
                    token_usage = ai_scan_raw.get('token_usage', {})
                    if token_usage:
                        ai_cost_data = {
                            'depth': ai_scan_raw.get('depth', 'unknown'),
                            'model': ai_scan_raw.get('model', 'unknown'),
                            'files_analyzed': ai_scan_raw.get('files_analyzed', 0),
                            'findings_count': ai_scan_raw.get('final_findings_count', 0),
                            'input_tokens': token_usage.get('input_tokens', 0),
                            'output_tokens': token_usage.get('output_tokens', 0),
                            'estimated_cost_usd': token_usage.get('estimated_cost_usd', 0),
                        }
            except Exception as e:
                logger.warning(f"Could not read AI scan cost data: {e}")

        # Convert markdown-style summary to HTML for safe template rendering
        from appsec_galaxy.reporting.ai_summary import _markdown_to_html
        ai_summary_html = _markdown_to_html(ai_summary) if ai_summary else ""

        # Structured stats for the executive summary tiles (rendered from
        # real counts, not parsed out of the narrative text)
        security = [f for f in findings if f.get('category') != 'code_quality']
        exec_stats: dict[str, Any] = {
            'critical': critical_count,
            'high': high_count,
            'sast': len([f for f in security if f.get('tool') == 'semgrep']),
            'secrets': len([f for f in security if f.get('tool') == 'gitleaks']),
            'deps': len([f for f in security if f.get('tool') == 'trivy']),
            'code_quality': len([f for f in findings if f.get('category') == 'code_quality']),
            'kev': len([f for f in findings if f.get('in_kev')]),
        }
        if critical_count > 0 or exec_stats['secrets'] > 0:
            exec_stats['risk_level'] = 'high'
            exec_stats['risk_label'] = 'High Risk'
        elif high_count > 0:
            exec_stats['risk_level'] = 'medium'
            exec_stats['risk_label'] = 'Medium Risk'
        else:
            exec_stats['risk_level'] = 'low'
            exec_stats['risk_label'] = 'Low Risk'

        # See justification at the Environment() construction above:
        # autoescape is enabled; ai_summary is pre-escaped HTML marked safe in the template.
        html_content = template.render(  # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
            results=sorted_results,
            total_findings=total_findings,
            critical_count=critical_count,
            high_count=high_count,
            ai_summary=ai_summary_html,
            repo_path=repo_path or "Unknown Repository",
            sbom_data=sbom_data,
            scan_timestamp=scan_timestamp,
            cross_file_enhanced_count=cross_file_enhanced_count,
            attack_chains_count=attack_chains_count,
            cross_file_context_data=cross_file_context_data,
            detected_languages=sorted(detected_languages) if detected_languages else [],
            dependency_health_data=dependency_health_template_data,
            ai_cross_file_data=ai_cross_file_data,
            ai_cost_data=ai_cost_data,
            exec_stats=exec_stats
        )

        # Write HTML report
        report_path = output_path / "report.html"
        report_path.write_text(html_content)
        logger.info(f"HTML report generated: {report_path}")
        return str(report_path)

    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        # Create fallback report
        fallback_html = """
        <html>
        <head><title>Security Scan Report</title></head>
        <body>
        <h1>Security Scan Report</h1>
        <p><strong>Error:</strong> Failed to generate full report.</p>
        <p>Check the logs for details.</p>
        </body>
        </html>
        """
        output_path = Path(output_dir)
        fallback_path = output_path / "report.html"
        fallback_path.write_text(fallback_html)
        return str(fallback_path)
