"""
Clippy code quality scanner for Rust.

Clippy is the official Rust linter with over 600 lint checks.
"""

from pathlib import Path
from .quality_scanner_base import QualityScannerBase


class ClippyScanner(QualityScannerBase):
    """Clippy scanner for Rust code quality."""

    @property
    def tool_name(self) -> str:
        return "clippy"

    @property
    def display_name(self) -> str:
        return "Clippy"

    @property
    def check_command(self) -> list[str]:
        return ['cargo', 'clippy', '--version']

    @property
    def languages(self) -> list[str]:
        return ['rust']

    def get_repo_config_paths(self, repo_path: Path) -> list[Path]:
        """Check for Clippy/Cargo config in repo."""
        return [
            repo_path / "clippy.toml",
            repo_path / ".clippy.toml",
            repo_path / "Cargo.toml",  # Clippy settings can be in [lints] section
        ]

    def get_bundled_config_path(self, repo_path: Path) -> Path | None:
        """Use AppSec Galaxy bundled Clippy config."""
        bundled = self.configs_dir / "clippy.toml"
        return bundled if bundled.exists() else None

    def build_scan_command(self, repo_path: Path, output_file: Path, config_path: Path | None) -> list[str]:
        """Build Clippy command."""
        cmd = [
            'cargo', 'clippy',
            '--message-format=json',
            '--all-targets',
            '--',
            '-W', 'clippy::all'
        ]

        # Config is auto-detected from clippy.toml or Cargo.toml in repo root
        # No need to pass config path explicitly

        return cmd

    def normalize_finding(self, raw_finding: dict, repo_path: Path) -> dict:
        """Convert Clippy finding to AppSec Galaxy format."""
        # Clippy JSON format: {"reason": "compiler-message", "message": {...}}
        message = raw_finding.get('message', {})

        # Get file path from spans
        spans = message.get('spans', [])
        file_path = spans[0].get('file_name', '') if spans else ''

        try:
            relative_path = Path(file_path).relative_to(repo_path) if file_path else Path(file_path)
        except ValueError:
            relative_path = Path(file_path)

        # Map Clippy severity
        level = message.get('level', 'warning')
        severity_map = {
            'error': 'high',
            'warning': 'medium',
            'note': 'low',
            'help': 'low'
        }
        severity = severity_map.get(level, 'medium')

        # Extract line/column from first span
        line_start = spans[0].get('line_start', 0) if spans else 0
        col_start = spans[0].get('column_start', 0) if spans else 0
        line_end = spans[0].get('line_end', line_start) if spans else line_start
        col_end = spans[0].get('column_end', col_start) if spans else col_start

        # Extract lint code (e.g., "clippy::needless_return")
        code = message.get('code', {}).get('code', 'clippy-lint')

        return {
            'tool': 'clippy',
            'category': 'code_quality',
            'severity': severity,
            'check_id': code,
            'path': str(relative_path),
            'start': {
                'line': line_start,
                'col': col_start
            },
            'end': {
                'line': line_end,
                'col': col_end
            },
            'extra': {
                'message': message.get('message', ''),
                'metadata': {
                    'category': 'code_quality',
                    'subcategory': 'best-practice',
                    'technology': ['rust'],
                    'confidence': 'HIGH'
                }
            }
        }

    def extract_findings_from_output(self, raw_results: any) -> list[dict]:
        """Extract findings from Clippy JSON output."""
        # Clippy outputs newline-delimited JSON
        # Each line is a separate JSON object
        findings = []

        if isinstance(raw_results, list):
            # Already parsed as list
            for item in raw_results:
                if isinstance(item, dict) and item.get('reason') == 'compiler-message':
                    message = item.get('message', {})
                    # Only include warnings/errors from clippy lints
                    code = message.get('code', {}).get('code', '')
                    if code and ('clippy::' in code or message.get('level') in ['error', 'warning']):
                        findings.append(item)

        return findings


# Export scanner function for main.py
def run_clippy(repo_path: str, output_dir: str = None) -> list:
    """Run Clippy quality scan."""
    scanner = ClippyScanner()
    return scanner.run_scan(repo_path, output_dir)
