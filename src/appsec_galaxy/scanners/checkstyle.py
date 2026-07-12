"""
Checkstyle code quality scanner for Java.

Checkstyle is the industry-standard code quality tool for Java.
"""

from pathlib import Path
from typing import Any
from .quality_scanner_base import QualityScannerBase


class CheckstyleScanner(QualityScannerBase):
    """Checkstyle scanner for Java code quality."""

    @property
    def tool_name(self) -> str:
        return "checkstyle"

    @property
    def display_name(self) -> str:
        return "Checkstyle"

    @property
    def check_command(self) -> list[str]:
        return ['checkstyle', '--version']

    @property
    def languages(self) -> list[str]:
        return ['java']

    def get_repo_config_paths(self, repo_path: Path) -> list[Path]:
        """Check for Checkstyle config in repo."""
        return [
            repo_path / "checkstyle.xml",
            repo_path / ".checkstyle.xml",
            repo_path / "config" / "checkstyle" / "checkstyle.xml",
        ]

    def get_bundled_config_path(self, repo_path: Path) -> Path | None:
        """Use AppSec Galaxy bundled Checkstyle config."""
        bundled = self.configs_dir / "checkstyle.xml"
        return bundled if bundled.exists() else None

    def build_scan_command(self, repo_path: Path, output_file: Path, config_path: Path | None) -> list[str]:
        """Build Checkstyle command."""
        cmd = ['checkstyle']

        # Add config
        if config_path:
            cmd.extend(['-c', str(config_path)])

        # Output format - Checkstyle 10+ uses XML (JSON not supported)
        cmd.extend(['-f', 'xml', '-o', str(output_file)])

        # Scan all Java files
        java_files = list(repo_path.rglob('*.java'))
        # Filter excluded dirs
        java_files = [f for f in java_files if not any(
            excluded in f.parts
            for excluded in ['target', 'build', '.git', 'node_modules']
        )]

        if java_files:
            # Use relative paths since we run from cwd=repo_path
            relative_files = [str(f.relative_to(repo_path)) for f in java_files[:500]]
            cmd.extend(relative_files)  # Limit to 500 files
            self.logger.debug(f"Checkstyle scanning {len(relative_files)} Java files")

        return cmd

    def normalize_finding(self, raw_finding: dict, repo_path: Path) -> dict:
        """Convert Checkstyle finding to AppSec Galaxy format."""
        file_path = Path(raw_finding.get('fileName', ''))
        try:
            relative_path = file_path.relative_to(repo_path)
        except ValueError:
            relative_path = file_path

        # Map Checkstyle severity
        severity_map = {
            'error': 'high',
            'warning': 'medium',
            'info': 'low'
        }
        severity = severity_map.get(raw_finding.get('severity', 'warning').lower(), 'medium')

        return {
            'tool': 'checkstyle',
            'category': 'code_quality',
            'severity': severity,
            'check_id': raw_finding.get('source', 'checkstyle-rule'),
            'path': str(relative_path),
            'start': {
                'line': raw_finding.get('lineNumber', 0),
                'col': raw_finding.get('columnNumber', 0)
            },
            'end': {
                'line': raw_finding.get('lineNumber', 0),
                'col': raw_finding.get('columnNumber', 0)
            },
            'extra': {
                'message': raw_finding.get('message', ''),
                'metadata': {
                    'category': 'code_quality',
                    'subcategory': 'best-practice',
                    'technology': ['java'],
                    'confidence': 'HIGH'
                }
            }
        }

    def parse_output(self, output_file: Path, repo_path: Path) -> list[dict]:
        """Parse Checkstyle XML output."""
        if not output_file.exists():
            self.logger.warning("Checkstyle did not produce an output file")
            return []

        try:
            # XXE defense: Checkstyle output is parsed; even though AppSec Galaxy
            # invokes Checkstyle itself, the XML is downstream of untrusted
            # repo content and defensive parsing is cheap.
            import defusedxml.ElementTree as ET
            tree = ET.parse(output_file)
            root = tree.getroot()

            findings = []
            for file_elem in root.findall('file'):
                file_name = file_elem.get('name', '')

                for error_elem in file_elem.findall('error'):
                    raw_finding = {
                        'fileName': file_name,
                        'lineNumber': int(error_elem.get('line', 0)),
                        'columnNumber': int(error_elem.get('column', 0)),
                        'severity': error_elem.get('severity', 'warning'),
                        'message': error_elem.get('message', ''),
                        'source': error_elem.get('source', 'checkstyle-rule')
                    }

                    try:
                        normalized = self.normalize_finding(raw_finding, repo_path)
                        findings.append(normalized)
                    except Exception as e:
                        self.logger.debug(f"Failed to normalize finding: {e}")

            return findings

        except Exception as e:
            self.logger.error(f"Failed to parse Checkstyle XML output: {e}")
            return []

    def extract_findings_from_output(self, raw_results: Any) -> list[dict]:
        """Not used - parse_output is overridden for XML parsing."""
        return []


# Export scanner function for main.py
def run_checkstyle(repo_path: str, output_dir: str | None = None) -> list:
    """Run Checkstyle quality scan."""
    scanner = CheckstyleScanner()
    return scanner.run_scan(repo_path, output_dir)
