#!/usr/bin/env python3
"""
Cross-File Analysis Integration for AppSec Galaxy

This module integrates the cross-file analyzer with the main scanner to provide
enhanced AI-powered vulnerability analysis with deep codebase understanding.
Uses the CrossFileAnalyzer from cross_file_analyzer.py for actual cross-file analysis.
"""

from pathlib import Path
from typing import Any
import logging

# Import the cross-file analyzer functions
try:
    from .cross_file_analyzer import CrossFileAnalyzer
except ImportError:
    from appsec_galaxy.cross_file_analyzer import CrossFileAnalyzer

logger = logging.getLogger(__name__)

class CrossFileEnhancedAnalyzer:
    """Enhanced vulnerability analysis using CrossFileAnalyzer"""

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.codebase_context: dict[str, Any] | None = None
        self.cross_file_analysis: dict[str, Any] | None = None
        self.cross_file_analyzer = CrossFileAnalyzer(repo_path)

    async def analyze_codebase_context(self) -> dict[str, Any]:
        """Analyze the codebase using CrossFileAnalyzer"""
        try:
            # Use cross-file analyzer for comprehensive analysis
            structure = self.cross_file_analyzer.analyze_repository_structure()

            self.codebase_context = {
                "repo_path": self.repo_path,
                "structure": structure,
                "security_context": self._build_security_context(structure)
            }

            logger.info(f"🧠 Cross-file codebase analysis complete: {structure['total_files']} files, {len(structure['languages'])} languages, {len(structure['frameworks'])} frameworks")
            return self.codebase_context

        except Exception as e:
            logger.error(f"Failed to analyze codebase context: {e}")
            return {}

    def _build_security_context(self, structure: dict[str, Any]) -> dict[str, Any]:
        """Build security-specific context from codebase structure"""
        security_context: dict[str, Any] = {
            "risk_factors": [],
            "security_recommendations": [],
            "framework_specific_risks": [],
            "attack_surface": {}
        }

        # Analyze risk factors based on technologies used
        languages = structure.get('languages', [])
        frameworks = structure.get('frameworks', [])

        # Language-specific risks
        if 'javascript' in languages:
            security_context["risk_factors"].append("JavaScript - XSS and prototype pollution risks")
            security_context["attack_surface"]["client_side"] = "JavaScript execution context"

        if 'python' in languages:
            security_context["risk_factors"].append("Python - Code injection via eval/exec")
            security_context["attack_surface"]["server_side"] = "Python execution context"

        if 'java' in languages:
            security_context["risk_factors"].append("Java - Deserialization attacks, XXE vulnerabilities")
            security_context["attack_surface"]["jvm"] = "Java Virtual Machine context"

        if 'go' in languages:
            security_context["risk_factors"].append("Go - Path traversal, unsafe reflection")
            security_context["attack_surface"]["go_runtime"] = "Go runtime environment"

        if 'rust' in languages:
            security_context["risk_factors"].append("Rust - Memory safety, but unsafe blocks can introduce vulnerabilities")
            security_context["attack_surface"]["rust_runtime"] = "Rust runtime with unsafe blocks"

        if 'php' in languages:
            security_context["risk_factors"].append("PHP - Code injection, file inclusion vulnerabilities")
            security_context["attack_surface"]["php_runtime"] = "PHP execution context"

        # Framework-specific risks
        if 'express' in frameworks:
            security_context["framework_specific_risks"].append("Express.js - Missing security headers, CSRF vulnerabilities")

        if 'flask' in frameworks:
            security_context["framework_specific_risks"].append("Flask - Debug mode, insecure session management")

        if 'django' in frameworks:
            security_context["framework_specific_risks"].append("Django - SQL injection, admin interface exposure")

        if 'spring' in frameworks:
            security_context["framework_specific_risks"].append("Spring - Deserialization, SpEL injection, actuator exposure")

        # Security recommendations
        security_context["security_recommendations"] = self._generate_recommendations(structure)

        return security_context

    async def analyze_cross_file_relationships(self) -> dict[str, Any]:
        """Analyze relationships between files using CrossFileAnalyzer"""
        try:
            logger.info("🔍 Starting cross-file vulnerability analysis...")

            # Use cross-file analyzer for attack chain detection
            attack_chains = self.cross_file_analyzer.find_attack_chains()

            # Build cross-file analysis using cross-file analyzer data
            self.cross_file_analysis = {
                "attack_chains": [{
                    "vulnerability_type": chain.vulnerability_type,
                    "entry_point": chain.entry_point,
                    "attack_path": chain.attack_path,
                    "sink": chain.sink,
                    "severity": chain.severity,
                    "business_impact": chain.business_impact,
                    "description": chain.description,
                    "recommendation": chain.remediation
                } for chain in attack_chains],
                "cross_file_vulnerabilities": [{
                    "vulnerability_type": chain.vulnerability_type,
                    "severity": chain.severity.upper(),
                    "entry_point": chain.entry_point,
                    "sink": chain.sink,
                    "paths": [chain.attack_path],
                    "description": chain.description,
                    "recommendation": chain.remediation
                } for chain in attack_chains],
                "attack_paths": {
                    "chain_attacks": [{
                        "vulnerability": chain.vulnerability_type,
                        "severity": chain.severity.upper(),
                        "attack_steps": self._generate_attack_steps_from_chain(chain),
                        "impact": self._assess_chain_impact(chain),
                        "mitigation": chain.remediation
                    } for chain in attack_chains]
                }
            }

            logger.info(f"🔍 Cross-file analysis complete: {len(attack_chains)} attack chains identified")
            return self.cross_file_analysis

        except Exception as e:
            logger.error(f"Failed to analyze cross-file relationships: {e}")
            return {}

    def _generate_attack_steps_from_chain(self, chain) -> list[str]:
        """Generate attack steps from cross-file attack chain"""
        steps = [
            f"1. Attacker identifies entry point in {Path(chain.entry_point).name}",
            f"2. Attacker crafts {chain.vulnerability_type} payload",
            f"3. Payload flows through {len(chain.attack_path)-2} intermediate files" if len(chain.attack_path) > 2 else "3. Payload flows directly to target",
            f"4. Malicious operation executes in {Path(chain.sink).name}"
        ]
        return steps

    def _assess_chain_impact(self, chain) -> dict[str, str]:
        """Assess impact of cross-file attack chain"""
        impact_map = {
            'sql_injection': {"confidentiality": "High", "integrity": "High", "availability": "Medium"},
            'xss': {"confidentiality": "Medium", "integrity": "Medium", "availability": "Low"},
            'command_injection': {"confidentiality": "High", "integrity": "High", "availability": "High"},
            'path_traversal': {"confidentiality": "High", "integrity": "Medium", "availability": "Low"},
        }
        return impact_map.get(chain.vulnerability_type, {"confidentiality": "Medium", "integrity": "Medium", "availability": "Low"})

    def _generate_recommendations(self, structure: dict[str, Any]) -> list[str]:
        """Generate security recommendations based on codebase analysis"""
        recommendations = []

        languages = structure.get('languages', [])
        frameworks = structure.get('frameworks', [])

        # Language-specific recommendations
        if 'javascript' in languages:
            recommendations.extend([
                "Implement Content Security Policy (CSP) to prevent XSS",
                "Use input validation and sanitization libraries",
                "Avoid using eval() and innerHTML with user data"
            ])

        if 'python' in languages:
            recommendations.extend([
                "Use parameterized queries to prevent SQL injection",
                "Implement proper input validation with libraries like marshmallow",
                "Avoid using eval() and exec() with user input"
            ])

        # Framework-specific recommendations
        if 'express' in frameworks:
            recommendations.extend([
                "Use helmet.js for security headers",
                "Implement rate limiting with express-rate-limit",
                "Use express-validator for input validation"
            ])

        if 'flask' in frameworks:
            recommendations.extend([
                "Use Flask-Talisman for security headers",
                "Implement CSRF protection with Flask-WTF",
                "Use Flask-Limiter for rate limiting"
            ])

        # General recommendations
        recommendations.extend([
            "Implement proper authentication and authorization",
            "Use HTTPS for all communications",
            "Regular dependency updates and vulnerability scanning",
            "Implement proper logging and monitoring"
        ])

        return recommendations

    def _should_use_compact_mode(self, current_finding: dict[str, Any]) -> bool:
        """Determine if we should use compact mode based on finding patterns"""
        # Check for indicators of intentionally vulnerable test repos
        file_path = current_finding.get('path', '')

        # Common patterns in vulnerable test repos
        vulnerable_indicators = [
            'dvwa', 'webgoat', 'damn', 'vulnerable', 'vuln', 'test', 'demo',
            'juice-shop', 'mutillidae', 'bwapp', 'exploit', 'hack'
        ]

        path_lower = file_path.lower()
        if any(indicator in path_lower for indicator in vulnerable_indicators):
            return True

        # If we have many similar findings (common check_id pattern)
        if hasattr(self, '_finding_counts'):
            check_id = current_finding.get('check_id', '')
            base_check = check_id.split('.')[-1] if '.' in check_id else check_id
            similar_count = self._finding_counts.get(base_check, 0)

            # Use compact mode if we have 5+ similar findings
            if similar_count >= 5:
                return True

        return False

    def _track_finding_patterns(self, findings: list[dict[str, Any]]) -> None:
        """Track patterns in findings for adaptive sizing"""
        self._finding_counts: dict[str, int] = {}
        for finding in findings:
            check_id = finding.get('check_id', '')
            base_check = check_id.split('.')[-1] if '.' in check_id else check_id
            self._finding_counts[base_check] = self._finding_counts.get(base_check, 0) + 1

    def _generate_pr_summary(self, findings: list[dict[str, Any]]) -> str:
        """Generate PR comment summary with cross-file insights"""
        total_findings = len(findings)
        critical_count = len([f for f in findings if f.get('severity', '').lower() == 'critical'])
        high_count = len([f for f in findings if f.get('severity', '').lower() in ['high', 'error']])

        # Get cross-file analysis insights
        frameworks = (self.codebase_context or {}).get('structure', {}).get('frameworks', [])
        attack_chains = len(self.cross_file_analysis.get('attack_chains', [])) if self.cross_file_analysis else 0

        summary = f"""## 🔒 Security Scan Results

**Summary:** {total_findings} security findings detected

### Severity Breakdown
- 🔴 Critical: {critical_count}
- 🟠 High: {high_count}
- 🟡 Medium: {total_findings - critical_count - high_count}

### Cross-File Analysis
"""

        if frameworks:
            summary += f"- **Tech Stack:** {', '.join(frameworks[:2])}\n"

        if attack_chains > 0:
            summary += f"- **Cross-file Analysis:** {attack_chains} attack chains identified\n"
        else:
            summary += "- **Cross-file Analysis:** No significant cross-file vulnerabilities detected\n"

        # Add framework-specific recommendations
        if frameworks:
            if 'express' in frameworks:
                summary += "- **Express.js Recommendation:** Implement helmet.js for security headers\n"
            elif 'flask' in frameworks:
                summary += "- **Flask Recommendation:** Use Flask-Talisman for security headers\n"

        summary += "\n*🧠 Generated by AppSec Galaxy with Cross-File Intelligence*"

        return summary

    def enhance_vulnerability_analysis(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Enhance vulnerability findings with cross-file analysis context"""
        if not self.codebase_context:
            logger.warning("No codebase context available for enhancement")
            return findings

        # Track finding patterns for adaptive sizing
        self._track_finding_patterns(findings)

        # Reset attack pattern tracking for this batch
        self._seen_attack_patterns: set[str] = set()

        enhanced_findings = []

        for finding in findings:
            enhanced_finding = finding.copy()

            # Add context-aware analysis
            cross_file_analysis = self._analyze_finding_with_context(finding)
            enhanced_finding["cross_file_analysis"] = cross_file_analysis

            # Add business impact assessment
            business_impact = self._assess_business_impact(finding)
            enhanced_finding["business_impact"] = business_impact

            # Add context-aware remediation suggestions
            enhanced_remediation = self._generate_contextual_remediation(finding)
            enhanced_finding["enhanced_remediation"] = enhanced_remediation

            # Add cross-file vulnerability analysis
            cross_file_analysis = self._analyze_cross_file_implications(finding)
            enhanced_finding["cross_file_analysis"] = cross_file_analysis

            # Create visible cross-file analysis summary for reports
            enhanced_finding["cross_file_summary"] = self._create_cross_file_summary(finding, cross_file_analysis, business_impact, enhanced_remediation)

            enhanced_findings.append(enhanced_finding)

        return enhanced_findings

    def _create_cross_file_summary(self, finding: dict[str, Any], cross_file_analysis: dict[str, Any], business_impact: dict[str, Any], enhanced_remediation: dict[str, Any]) -> str:
        """Create a concise cross-file analysis summary for display in reports with adaptive sizing"""
        vuln_type = finding.get('check_id', 'Unknown').split('.')[-1].replace('-', ' ').title()
        file_path = finding.get('path', 'Unknown file')
        line_number = finding.get('line', 'N/A')
        severity = finding.get('severity', 'unknown').upper()

        # Create unique identifier for this finding
        finding_id = f"{Path(file_path).name}:{line_number}" if line_number != 'N/A' else Path(file_path).name

        # Get specific vulnerability context from the actual finding message
        finding.get('message', '')[:60] if finding.get('message') else vuln_type

        # Adaptive sizing based on context - shorter for intentionally vulnerable repos
        # Check if we're dealing with many similar findings (common in test repos)
        is_compact_mode = self._should_use_compact_mode(finding)

        # Get framework context
        structure = (self.codebase_context or {}).get('structure', {})
        frameworks = structure.get('frameworks', [])
        structure.get('languages', [])

        summary_parts = []

        # Get tool that found this vulnerability
        tool = finding.get('tool', 'unknown')

        # Handle different vulnerability types differently
        file_name = Path(file_path).name if file_path != 'Unknown file' else 'Unknown file'

        # Dependency vulnerabilities (Trivy findings)
        if tool == 'trivy' or file_name in ['package-lock.json', 'package.json', 'requirements.txt', 'pom.xml', 'go.mod', 'Cargo.toml']:
            summary_parts.append(f"Dependency vuln in {file_name}")

            # Extract package info from finding
            package_name = self._extract_package_name(finding)
            if package_name:
                summary_parts.append(f"Package: {package_name}")

            # Add CVE or vulnerability details
            cve_id = finding.get('cve', '') or finding.get('vulnerability_id', '')
            if cve_id:
                summary_parts.append(f"CVE: {cve_id}")
            elif finding.get('message', ''):
                # Extract meaningful part of message with adaptive truncation
                message = finding.get('message', '')
                max_len = 80 if is_compact_mode else 120
                if len(message) > max_len:
                    # Find natural break point at word boundary
                    truncated = message[:max_len-3]
                    last_space = truncated.rfind(' ')
                    if last_space > max_len*0.7:  # Only break at word if not too short
                        message = message[:last_space] + "..."
                    else:
                        message = message[:max_len-3] + "..."
                summary_parts.append(f"Issue: {message}")

            # Add dependency-specific impact
            if 'critical' in severity.lower() or 'high' in severity.lower():
                summary_parts.append("High impact dependency")

            # Add dependency-specific remediation
            immediate_actions = enhanced_remediation.get('immediate_actions', [])
            if immediate_actions:
                action = immediate_actions[0]
                if len(action) > 80:
                    # Find natural break point for fix description
                    truncated = action[:77]
                    last_space = truncated.rfind(' ')
                    if last_space > 50:
                        action = action[:last_space] + "..."
                    else:
                        action = action[:77] + "..."
                summary_parts.append(f"Fix: {action}")
            else:
                summary_parts.append("Fix: Update to secure version")

        # Code vulnerabilities (Semgrep/Gitleaks findings) - Keep it clean
        else:
            # Just add file location - much cleaner
            if line_number != 'N/A':
                summary_parts.append(f"Found in {file_name}:{line_number}")
            else:
                summary_parts.append(f"Found in {file_name}")

            # For SAST findings, only add attack info if it's truly unique
            cross_file_analysis = self._analyze_cross_file_implications(finding)
            attack_chains = cross_file_analysis.get('potential_attack_chains', [])
            if attack_chains and not is_compact_mode:  # Skip attack details in compact mode
                chain = attack_chains[0]
                entry_file = Path(chain.get('entry_point', '')).name
                sink_file = Path(chain.get('sink', '')).name

                # Only show attack flow if files are different (cross-file)
                if entry_file and sink_file and entry_file != sink_file:
                    summary_parts.append(f"Flows to {sink_file}")
            elif is_compact_mode:
                # In compact mode, just indicate if it's part of an attack chain
                if attack_chains:
                    summary_parts.append("Cross-file vuln")

            # Skip the debug info - too noisy

            # Add business impact with adaptive justification length
            impact_justification = business_impact.get('business_justification', '')
            if impact_justification:
                # Shorter impact descriptions in compact mode
                max_impact_len = 90 if is_compact_mode else 140
                if len(impact_justification) > max_impact_len:
                    truncated = impact_justification[:max_impact_len-3]
                    last_space = truncated.rfind(' ')
                    if last_space > max_impact_len*0.7:
                        justification = impact_justification[:last_space] + "..."
                    else:
                        justification = impact_justification[:max_impact_len-3] + "..."
                else:
                    justification = impact_justification

                # Add line number context to business impact
                if line_number != 'N/A':
                    summary_parts.append(f"Impact (L{line_number}): {justification}")
                else:
                    summary_parts.append(f"Impact: {justification}")
            elif business_impact.get('financial_risk') == 'High':
                risk_detail = business_impact.get('context_factors', ['Unknown risk factors'])[0] if business_impact.get('context_factors') else 'Unknown risk factors'
                summary_parts.append(f"High Financial Risk: {risk_detail[:50]}..." if len(risk_detail) > 50 else f"High Financial Risk: {risk_detail}")

            # Add specific remediation with code context and line reference
            immediate_actions = enhanced_remediation.get('immediate_actions', [])
            if immediate_actions:
                action = immediate_actions[0]
                # Allow longer fix descriptions for code fixes
                if len(action) > 90:
                    truncated = action[:87]
                    last_space = truncated.rfind(' ')
                    if last_space > 60:
                        action = action[:last_space] + "..."
                    else:
                        action = action[:87] + "..."

                # Add line reference to fix if available
                if line_number != 'N/A' and 'sql' in vuln_type.lower():
                    summary_parts.append(f"Fix (L{line_number}): {action}")
                else:
                    summary_parts.append(f"Fix: {action}")

        # Add technology context as final element for all types
        if frameworks:
            tech_stack = ', '.join(frameworks[:2])
            summary_parts.append(f"Tech: {tech_stack}")

        if summary_parts:
            # Add unique identifier at the beginning for differentiation
            summary_with_id = f"[{finding_id}] {' | '.join(summary_parts)}"
            return f"Cross-File Analysis: {summary_with_id}"
        else:
            return f"Cross-File Analysis: [{finding_id}] {vuln_type} | Tech: {frameworks[0] if frameworks else 'multi-language'}"

    def _analyze_finding_with_context(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Analyze a finding with codebase context using real CrossFileAnalyzer data"""
        analysis: dict[str, Any] = {
            "severity_justification": "",
            "attack_vector": "",
            "likelihood": "",
            "context_factors": [],
            "cross_file_context": {},
            "data_flow_analysis": {}
        }

        # Get vulnerability details
        vuln_type = finding.get('check_id', '').lower()
        file_path = finding.get('path', '')
        line_number = finding.get('line', 'N/A')

        # Use cross-file analyzer data if available
        if self.codebase_context and self.cross_file_analysis:
            structure = self.codebase_context.get('structure', {})
            frameworks = structure.get('frameworks', [])

            # Check if file is an entry point or sink
            entry_points = structure.get('entry_points', [])
            sensitive_sinks = structure.get('sensitive_sinks', [])

            if file_path in entry_points:
                analysis["context_factors"].append("File is user-facing entry point")
                analysis["severity_justification"] = "High - vulnerability in user-accessible endpoint"

            if file_path in sensitive_sinks:
                analysis["context_factors"].append("File contains sensitive operations")
                analysis["likelihood"] = "High - direct access to sensitive functionality"

            # Analyze attack chains involving this file
            attack_chains = self.cross_file_analysis.get('attack_chains', [])
            related_chains = [chain for chain in attack_chains
                            if file_path in chain.get('attack_path', []) or
                               file_path == chain.get('entry_point', '') or
                               file_path == chain.get('sink', '')]

            if related_chains:
                chain = related_chains[0]  # Use first relevant chain
                analysis["cross_file_context"] = {
                    "part_of_attack_chain": True,
                    "chain_type": chain.get('vulnerability_type', ''),
                    "chain_severity": chain.get('severity', ''),
                    "attack_path_length": len(chain.get('attack_path', [])),
                    "business_impact": chain.get('business_impact', '')
                }

                if file_path == chain.get('entry_point', ''):
                    analysis["attack_vector"] = f"Entry point for {chain.get('vulnerability_type', 'unknown')} attack chain reaching {Path(chain.get('sink', '')).name}"
                elif file_path == chain.get('sink', ''):
                    analysis["attack_vector"] = f"Sink for {chain.get('vulnerability_type', 'unknown')} attack chain from {Path(chain.get('entry_point', '')).name}"
                else:
                    analysis["attack_vector"] = f"Intermediate step in {chain.get('vulnerability_type', 'unknown')} attack chain"

                analysis["likelihood"] = "High - part of confirmed cross-file attack chain"
                analysis["context_factors"].append(f"Part of {len(chain.get('attack_path', []))} file attack chain")

            # Framework-specific analysis with real context
            if 'express' in frameworks:
                if 'xss' in vuln_type:
                    analysis["attack_vector"] = f"XSS in Express.js route at {file_path}:{line_number}"
                elif 'sql' in vuln_type:
                    analysis["attack_vector"] = f"SQL injection in Express.js handler at {file_path}:{line_number}"

            # Check for sensitive file locations
            if any(sensitive in file_path.lower() for sensitive in ['auth', 'login', 'admin', 'payment', 'user']):
                analysis["severity_justification"] = f"Critical - vulnerability in security-sensitive component ({file_path}:{line_number})"
                analysis["context_factors"].append("Located in authentication/payment critical path")

        return analysis

    def _assess_business_impact(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Assess business impact using cross-file analyzer with enhanced context"""
        # Get base assessment from cross-file analyzer
        base_impact = self.cross_file_analyzer.assess_business_impact(finding)

        # Enhance with cross-file analysis context
        file_path = finding.get('path', '')
        vuln_type = finding.get('check_id', '').lower()

        enhanced_impact = base_impact.copy()

        # Add cross-file attack chain context to business impact
        if self.cross_file_analysis:
            attack_chains = self.cross_file_analysis.get('attack_chains', [])
            related_chains = [chain for chain in attack_chains
                            if file_path in chain.get('attack_path', []) or
                               file_path == chain.get('entry_point', '') or
                               file_path == chain.get('sink', '')]

            if related_chains:
                chain = related_chains[0]
                chain_impact = chain.get('business_impact', '')

                # Upgrade business impact if part of attack chain
                if 'high' in chain_impact.lower():
                    enhanced_impact["financial_risk"] = "High"
                    enhanced_impact["reputation_risk"] = "High"
                    enhanced_impact["business_justification"] = f"{chain_impact} - This vulnerability is part of a {len(chain.get('attack_path', []))} file attack chain from {Path(chain.get('entry_point', '')).name} to {Path(chain.get('sink', '')).name}"

                enhanced_impact["context_factors"].append(f"Part of cross-file attack chain: {chain.get('vulnerability_type', 'unknown')}")
                enhanced_impact["attack_chain_details"] = {
                    "chain_type": chain.get('vulnerability_type', ''),
                    "entry_point": Path(chain.get('entry_point', '')).name,
                    "sink": Path(chain.get('sink', '')).name,
                    "path_length": len(chain.get('attack_path', [])),
                    "severity": chain.get('severity', '')
                }

        # Add specific file context to justification
        if not enhanced_impact.get("business_justification"):
            file_name = Path(file_path).name
            if 'sql' in vuln_type:
                enhanced_impact["business_justification"] = f"SQL injection in {file_name} can lead to database compromise and data theft"
            elif 'secret' in vuln_type:
                enhanced_impact["business_justification"] = f"Exposed credentials in {file_name} enable unauthorized system access"
            elif 'xss' in vuln_type:
                enhanced_impact["business_justification"] = f"XSS vulnerability in {file_name} can compromise user sessions and data"

        return enhanced_impact

    def _generate_contextual_remediation(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Generate context-aware remediation suggestions"""
        remediation: dict[str, Any] = {
            "immediate_actions": [],
            "long_term_solutions": [],
            "code_examples": [],
            "framework_specific": []
        }

        vuln_type = finding.get('check_id', '').lower()

        if not self.codebase_context:
            return remediation

        structure = self.codebase_context.get('structure', {})
        frameworks = structure.get('frameworks', [])
        languages = structure.get('languages', [])

        # SQL Injection remediation
        if 'sql' in vuln_type:
            remediation["immediate_actions"].append("Replace dynamic SQL with parameterized queries")

            if 'python' in languages:
                remediation["code_examples"].append(
                    "# Instead of: cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
                    "# Use: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
                )

            if 'javascript' in languages:
                remediation["code_examples"].append(
                    "// Instead of: db.query(`SELECT * FROM users WHERE id = ${userId}`)\n"
                    "// Use: db.query('SELECT * FROM users WHERE id = ?', [userId])"
                )

        # XSS remediation
        if 'xss' in vuln_type:
            remediation["immediate_actions"].append("Implement output encoding/escaping")

            if 'express' in frameworks:
                remediation["framework_specific"].append("Use helmet.js for XSS protection headers")
                remediation["code_examples"].append(
                    "const helmet = require('helmet');\n"
                    "app.use(helmet.contentSecurityPolicy());"
                )

        # Secret exposure remediation
        if 'secret' in vuln_type or 'credential' in vuln_type:
            remediation["immediate_actions"].extend([
                "Remove hardcoded secrets from code",
                "Rotate exposed credentials immediately",
                "Use environment variables or secret management"
            ])

            remediation["code_examples"].append(
                "# Instead of: API_KEY = 'hardcoded-secret'\n"
                "# Use: API_KEY = os.getenv('API_KEY')"
            )

        return remediation

    def _extract_package_name(self, finding: dict[str, Any]) -> str:
        """Extract package name from a dependency vulnerability finding"""
        # Try various fields where package name might be stored
        package_name = (finding.get('package', '') or
                       finding.get('library', '') or
                       finding.get('component', '') or
                       finding.get('dependency', ''))

        # If not found, try to extract from message or description
        if not package_name:
            message = finding.get('message', '') or finding.get('description', '')
            # Look for package name patterns in message
            import re
            # Match patterns like "package: name" or "library name"
            match = re.search(r'(?:package|library|dependency|component):\s*([^\s,]+)', message, re.IGNORECASE)
            if match:
                package_name = match.group(1)
            else:
                # Try to extract first quoted string which might be package name
                quoted_match = re.search(r'["\']([^"\']+)["\']', message)
                if quoted_match:
                    package_name = quoted_match.group(1)

        return package_name[:30] if package_name else ''  # Limit length

    def _analyze_cross_file_implications(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Analyze cross-file implications using cross-file analyzer data with detailed context"""
        cross_file_analysis: dict[str, Any] = {
            "affected_files": [],
            "data_flow_paths": [],
            "potential_attack_chains": [],
            "related_vulnerabilities": [],
            "cross_file_context": {}
        }

        if not self.cross_file_analysis:
            return cross_file_analysis

        file_path = finding.get('path', '')
        finding.get('check_id', '').lower()
        line_number = finding.get('line', 'N/A')

        # Analyze attack chains involving this specific file
        attack_chains = self.cross_file_analysis.get("attack_chains", [])

        for chain in attack_chains:
            entry_point = chain.get("entry_point", "")
            sink = chain.get("sink", "")
            attack_path = chain.get("attack_path", [])

            # Check if current file is involved in this attack chain
            file_in_chain = (file_path == entry_point or
                           file_path == sink or
                           file_path in attack_path or
                           any(file_path in path_file for path_file in attack_path))

            if file_in_chain:
                # Determine role in attack chain
                role = "intermediate"
                if file_path == entry_point:
                    role = "entry_point"
                elif file_path == sink:
                    role = "sink"

                chain_details = {
                    "chain_type": chain.get("vulnerability_type", ""),
                    "severity": chain.get("severity", ""),
                    "description": chain.get("description", ""),
                    "remediation": chain.get("remediation", ""),
                    "business_impact": chain.get("business_impact", ""),
                    "role_in_chain": role,
                    "entry_point": Path(entry_point).name if entry_point else "Unknown",
                    "sink": Path(sink).name if sink else "Unknown",
                    "attack_path": [Path(p).name for p in attack_path],
                    "path_length": len(attack_path),
                    "full_entry_point": entry_point,
                    "full_sink": sink
                }

                cross_file_analysis["potential_attack_chains"].append(chain_details)

                # Add affected files from the attack path
                cross_file_analysis["affected_files"].extend([Path(p).name for p in attack_path if p != file_path])

                # Add data flow path description
                if role == "entry_point":
                    flow_description = f"Data flows from this file ({Path(file_path).name}:{line_number}) through {len(attack_path)-2} files to {Path(sink).name}"
                elif role == "sink":
                    flow_description = f"Data flows to this file ({Path(file_path).name}:{line_number}) from {Path(entry_point).name} through {len(attack_path)-2} files"
                else:
                    flow_description = f"Data flows through this file ({Path(file_path).name}:{line_number}) from {Path(entry_point).name} to {Path(sink).name}"

                cross_file_analysis["data_flow_paths"].append(flow_description)

        # Add cross-file context summary
        if cross_file_analysis["potential_attack_chains"]:
            primary_chain = cross_file_analysis["potential_attack_chains"][0]
            cross_file_analysis["cross_file_context"] = {
                "is_part_of_attack_chain": True,
                "primary_vulnerability": primary_chain["chain_type"],
                "chain_severity": primary_chain["severity"],
                "role": primary_chain["role_in_chain"],
                "affected_file_count": len(set(cross_file_analysis["affected_files"])),
                "attack_summary": f"{primary_chain['role_in_chain'].title()} in {primary_chain['chain_type']} attack from {primary_chain['entry_point']} to {primary_chain['sink']}"
            }
        else:
            cross_file_analysis["cross_file_context"] = {
                "is_part_of_attack_chain": False,
                "isolated_vulnerability": True,
                "attack_summary": f"Isolated vulnerability in {Path(file_path).name}:{line_number}"
            }

        return cross_file_analysis

    def generate_enhanced_report(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate an enhanced report with cross-file analysis context"""
        if not self.codebase_context:
            return {"error": "No codebase context available"}

        report = {
            "codebase_overview": self.codebase_context.get('structure', {}),
            "security_context": self.codebase_context.get('security_context', {}),
            "vulnerability_analysis": {
                "total_findings": len(findings),
                "critical_findings": len([f for f in findings if f.get('severity') == 'CRITICAL']),
                "high_findings": len([f for f in findings if f.get('severity') in ['HIGH', 'ERROR']]),
                "context_enhanced": True
            },
            "risk_assessment": self._generate_risk_assessment(findings),
            "strategic_recommendations": self._generate_strategic_recommendations(findings),
            "pr_summary": self._generate_pr_summary(findings)
        }

        return report

    def _generate_risk_assessment(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Generate a comprehensive risk assessment"""
        risk_assessment = {
            "overall_risk_level": "Low",
            "attack_surface_analysis": {},
            "threat_landscape": {},
            "compliance_impact": {}
        }

        # Calculate overall risk
        critical_count = len([f for f in findings if f.get('severity', '').lower() == 'critical'])
        high_count = len([f for f in findings if f.get('severity', '').lower() in ['high', 'error']])

        if critical_count > 0:
            risk_assessment["overall_risk_level"] = "Critical"
        elif high_count > 5:
            risk_assessment["overall_risk_level"] = "High"
        elif high_count > 0:
            risk_assessment["overall_risk_level"] = "Medium"

        # Analyze attack surface
        if self.codebase_context:
            structure = self.codebase_context.get('structure', {})
            risk_assessment["attack_surface_analysis"] = {
                "web_frameworks": structure.get('frameworks', []),
                "exposed_services": len(structure.get('entry_points', [])),
                "sensitive_data_exposure": len(structure.get('sensitive_files', []))
            }

        return risk_assessment

    def _generate_strategic_recommendations(self, findings: list[dict[str, Any]]) -> list[str]:
        """Generate strategic recommendations based on findings and context"""
        recommendations: list[str] = []

        if not self.codebase_context:
            return recommendations

        structure = self.codebase_context.get('structure', {})

        # Strategic recommendations based on findings
        critical_count = len([f for f in findings if f.get('severity') == 'CRITICAL'])
        if critical_count > 0:
            recommendations.append("Immediate action required: Address critical vulnerabilities within 24 hours")

        # Technology-specific recommendations
        if 'javascript' in structure.get('languages', []):
            recommendations.append("Implement comprehensive Content Security Policy (CSP)")

        if 'python' in structure.get('languages', []):
            recommendations.append("Integrate bandit static analysis into CI/CD pipeline")

        # Framework-specific recommendations
        if 'express' in structure.get('frameworks', []):
            recommendations.append("Implement security middleware stack with helmet.js")

        # General strategic recommendations
        recommendations.extend([
            "Establish regular security scanning in CI/CD pipeline",
            "Implement security training for development team",
            "Consider penetration testing for high-risk applications",
            "Establish incident response plan for security vulnerabilities"
        ])

        return recommendations


async def enhance_findings_with_cross_file(findings: list[dict[str, Any]], repo_path: str) -> list[dict[str, Any]]:
    """
    Enhance vulnerability findings using cross-file analysis.

    Two layers:
    1. Rule-based: AST/regex analysis of entry points, sinks, attack chains (always runs)
    2. AI-powered: LLM validates chains, correlates findings, checks sanitization
       (only runs when APPSEC_AI_SCAN=true)

    Args:
        findings: List of vulnerability findings
        repo_path: Path to the repository

    Returns:
        Enhanced findings with cross-file analysis context
    """
    try:
        analyzer = CrossFileEnhancedAnalyzer(repo_path)

        # Layer 1: Rule-based cross-file analysis (always runs)
        await analyzer.analyze_codebase_context()
        await analyzer.analyze_cross_file_relationships()
        enhanced_findings = analyzer.enhance_vulnerability_analysis(findings)

        logger.info(f"🧠 Enhanced {len(enhanced_findings)} findings with cross-file analysis context")

        # Layer 2: AI-powered enhancement (when APPSEC_AI_SCAN=true)
        try:
            import os
            import asyncio
            ai_enabled = os.getenv('APPSEC_AI_SCAN', 'false').lower() == 'true'
            if ai_enabled and analyzer.cross_file_analysis:
                from appsec_galaxy.ai_cross_file import run_ai_cross_file_analysis

                attack_chains = analyzer.cross_file_analysis.get('attack_chains', [])
                # Run synchronous AI calls in a worker thread so we don't
                # block the event loop while waiting on the LLM.
                ai_result = await asyncio.to_thread(
                    run_ai_cross_file_analysis,
                    enhanced_findings, attack_chains, repo_path
                )

                if ai_result.get('ai_enhanced'):
                    enhanced_findings = ai_result['enhanced_findings']
                    validated_chains = ai_result.get('validated_chains', [])
                    # Store validated chains back for reporting
                    analyzer.cross_file_analysis['attack_chains'] = validated_chains
                    analyzer.cross_file_analysis['ai_summary'] = ai_result.get('summary', {})

                    # Propagate AI fields back to per-finding chain snapshots.
                    # _analyze_cross_file_implications() snapshotted chains
                    # BEFORE AI ran, so we need to copy AI fields onto each
                    # finding's chain_details by matching on full paths + type.
                    chain_lookup = {}
                    for vc in validated_chains:
                        key = (
                            vc.get('entry_point', ''),
                            vc.get('sink', ''),
                            vc.get('vulnerability_type', ''),
                        )
                        chain_lookup[key] = vc

                    ai_chain_fields = (
                        'ai_validated', 'ai_exploitability', 'ai_confidence',
                        'ai_bypasses_needed', 'ai_severity_adjustment',
                        'ai_adjusted_severity',
                    )
                    for f in enhanced_findings:
                        cfa = f.get('cross_file_analysis') or {}
                        for chain in cfa.get('potential_attack_chains', []):
                            key = (
                                chain.get('full_entry_point', ''),
                                chain.get('full_sink', ''),
                                chain.get('chain_type', ''),
                            )
                            vc = chain_lookup.get(key)
                            if vc is None:
                                continue
                            for field in ai_chain_fields:
                                if field in vc:
                                    chain[field] = vc[field]

                    logger.info("🧠 AI-powered cross-file enhancement complete")
        except ImportError:
            logger.debug("AI cross-file module not available, skipping AI enhancement")
        except Exception as e:
            logger.warning(f"AI cross-file enhancement failed (rule-based results preserved): {e}")

        return enhanced_findings

    except Exception as e:
        logger.error(f"Failed to enhance findings with cross-file analysis: {e}")
        return findings

async def generate_cross_file_enhanced_report(findings: list[dict[str, Any]], repo_path: str) -> dict[str, Any]:
    """
    Generate an enhanced security report using cross-file analysis.

    Includes AI-powered insights when APPSEC_AI_SCAN=true.

    Args:
        findings: List of vulnerability findings
        repo_path: Path to the repository

    Returns:
        Enhanced security report
    """
    try:
        analyzer = CrossFileEnhancedAnalyzer(repo_path)

        # Analyze codebase context
        await analyzer.analyze_codebase_context()

        # Perform cross-file analysis
        await analyzer.analyze_cross_file_relationships()

        # Generate enhanced report
        report = analyzer.generate_enhanced_report(findings)

        # Add cross-file analysis to the report
        if analyzer.cross_file_analysis:
            report["cross_file_analysis"] = analyzer.cross_file_analysis

        # Add AI cross-file insights if available
        try:
            import os
            import asyncio
            ai_enabled = os.getenv('APPSEC_AI_SCAN', 'false').lower() == 'true'
            if ai_enabled and analyzer.cross_file_analysis:
                from appsec_galaxy.ai_cross_file import run_ai_cross_file_analysis

                attack_chains = analyzer.cross_file_analysis.get('attack_chains', [])
                ai_result = await asyncio.to_thread(
                    run_ai_cross_file_analysis,
                    findings, attack_chains, repo_path
                )

                if ai_result.get('ai_enhanced'):
                    report['ai_cross_file'] = ai_result.get('summary', {})
                    report['cross_file_analysis']['attack_chains'] = ai_result['validated_chains']
                    report['cross_file_analysis']['ai_summary'] = ai_result.get('summary', {})
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"AI cross-file enhancement for report failed: {e}")

        logger.info("🧠 Generated cross-file enhanced security report")
        return report

    except Exception as e:
        logger.error(f"Failed to generate cross-file enhanced report: {e}")
        return {"error": str(e)}
