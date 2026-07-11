"""
RuboCop code quality scanner for Ruby.

RuboCop is the de facto standard Ruby code style checker and linter.
"""

from pathlib import Path
from typing import Any
from .quality_scanner_base import QualityScannerBase


class RuboCopScanner(QualityScannerBase):
    """RuboCop scanner for Ruby code quality."""

    @property
    def tool_name(self) -> str:
        return "rubocop"

    @property
    def display_name(self) -> str:
        return "RuboCop"

    @property
    def check_command(self) -> list[str]:
        return ['rubocop', '--version']

    @property
    def languages(self) -> list[str]:
        return ['ruby']

    def get_repo_config_paths(self, repo_path: Path) -> list[Path]:
        """Check for RuboCop config in repo."""
        return [
            repo_path / ".rubocop.yml",
            repo_path / ".rubocop.yaml",
        ]

    def get_bundled_config_path(self, repo_path: Path) -> Path | None:
        """Use AppSec Galaxy bundled RuboCop config."""
        bundled = self.configs_dir / "rubocop.yml"
        return bundled if bundled.exists() else None

    def build_scan_command(self, repo_path: Path, output_file: Path, config_path: Path | None) -> list[str]:
        """Build RuboCop command."""
        cmd = ['rubocop']

        # Add config
        if config_path:
            cmd.extend(['--config', str(config_path)])

        # Output format
        cmd.extend(['--format', 'json', '--out', str(output_file)])

        # Scan all Ruby files
        cmd.append('.')

        return cmd

    def normalize_finding(self, raw_finding: dict, repo_path: Path) -> dict:
        """Convert RuboCop finding to AppSec Galaxy format."""
        file_path = Path(raw_finding.get('path', ''))
        try:
            relative_path = file_path.relative_to(repo_path)
        except ValueError:
            relative_path = file_path

        # Map RuboCop severity
        severity_map = {
            'fatal': 'critical',
            'error': 'high',
            'warning': 'medium',
            'convention': 'low',
            'refactor': 'low',
            'info': 'low'
        }
        severity = severity_map.get(raw_finding.get('severity', 'warning').lower(), 'medium')

        location = raw_finding.get('location', {})

        return {
            'tool': 'rubocop',
            'category': 'code_quality',
            'severity': severity,
            'check_id': raw_finding.get('cop_name', 'rubocop-rule'),
            'path': str(relative_path),
            'start': {
                'line': location.get('start_line', 0),
                'col': location.get('start_column', 0)
            },
            'end': {
                'line': location.get('last_line', location.get('start_line', 0)),
                'col': location.get('last_column', location.get('start_column', 0))
            },
            'extra': {
                'message': raw_finding.get('message', ''),
                'metadata': {
                    'category': 'code_quality',
                    'subcategory': 'best-practice',
                    'technology': ['ruby'],
                    'confidence': 'HIGH',
                    'cop_name': raw_finding.get('cop_name')
                }
            }
        }

    def extract_findings_from_output(self, raw_results: Any) -> list[dict]:
        """Extract findings from RuboCop JSON."""
        if isinstance(raw_results, dict) and 'files' in raw_results:
            findings = []
            for file_entry in raw_results['files']:
                findings.extend(file_entry.get('offenses', []))
            return findings
        return []


# Export scanner function for main.py
def run_rubocop(repo_path: str, output_dir: str | None = None) -> list:
    """Run RuboCop quality scan."""
    scanner = RuboCopScanner()
    return scanner.run_scan(repo_path, output_dir)
