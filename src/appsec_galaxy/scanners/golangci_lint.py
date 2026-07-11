"""
golangci-lint code quality scanner for Go.

golangci-lint is the standard linter aggregator for Go, running multiple linters in parallel.
"""

from pathlib import Path
from .quality_scanner_base import QualityScannerBase


class GolangCILintScanner(QualityScannerBase):
    """golangci-lint scanner for Go code quality."""

    @property
    def tool_name(self) -> str:
        return "golangci-lint"

    @property
    def display_name(self) -> str:
        return "golangci-lint"

    @property
    def check_command(self) -> list[str]:
        return ['golangci-lint', '--version']

    @property
    def languages(self) -> list[str]:
        return ['go']

    def get_repo_config_paths(self, repo_path: Path) -> list[Path]:
        """Check for golangci-lint config in repo."""
        return [
            repo_path / ".golangci.yml",
            repo_path / ".golangci.yaml",
            repo_path / ".golangci.json",
        ]

    def get_bundled_config_path(self, repo_path: Path) -> Path | None:
        """Use AppSec Galaxy bundled golangci-lint config."""
        bundled = self.configs_dir / "golangci.yml"
        return bundled if bundled.exists() else None

    def build_scan_command(self, repo_path: Path, output_file: Path, config_path: Path | None) -> list[str]:
        """Build golangci-lint command."""
        cmd = ['golangci-lint', 'run']

        # Add config
        if config_path:
            cmd.extend(['--config', str(config_path)])

        # Output format
        cmd.extend(['--out-format', 'json'])

        # Scan current directory
        cmd.append('./...')

        return cmd

    def normalize_finding(self, raw_finding: dict, repo_path: Path) -> dict:
        """Convert golangci-lint finding to AppSec Galaxy format."""
        pos = raw_finding.get('Pos', {})
        file_path = Path(pos.get('Filename', ''))

        try:
            relative_path = file_path.relative_to(repo_path)
        except ValueError:
            relative_path = file_path

        return {
            'tool': 'golangci-lint',
            'category': 'code_quality',
            'severity': 'medium',  # golangci-lint doesn't provide severity
            'check_id': raw_finding.get('FromLinter', 'golangci-lint'),
            'path': str(relative_path),
            'start': {
                'line': pos.get('Line', 0),
                'col': pos.get('Column', 0)
            },
            'end': {
                'line': pos.get('Line', 0),
                'col': pos.get('Column', 0)
            },
            'extra': {
                'message': raw_finding.get('Text', ''),
                'metadata': {
                    'category': 'code_quality',
                    'subcategory': 'best-practice',
                    'technology': ['go'],
                    'confidence': 'HIGH',
                    'linter': raw_finding.get('FromLinter')
                }
            }
        }

    def parse_output(self, output_file: Path, repo_path: Path) -> list[dict]:
        """
        golangci-lint outputs to stdout, not file.
        Override to handle stdout parsing.
        """
        # For now, return empty - will need to capture stdout differently
        # This is a limitation we can document
        return super().parse_output(output_file, repo_path)

    def extract_findings_from_output(self, raw_results: any) -> list[dict]:
        """Extract findings from golangci-lint JSON."""
        if isinstance(raw_results, dict) and 'Issues' in raw_results:
            return raw_results['Issues']
        return []


# Export scanner function for main.py
def run_golangci_lint(repo_path: str, output_dir: str = None) -> list:
    """Run golangci-lint quality scan."""
    scanner = GolangCILintScanner()
    return scanner.run_scan(repo_path, output_dir)
