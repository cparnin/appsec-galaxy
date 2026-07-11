"""
PHPStan code quality scanner for PHP.

PHPStan focuses on finding errors in PHP code without running it.
"""

from pathlib import Path
from typing import Any
from .quality_scanner_base import QualityScannerBase


class PHPStanScanner(QualityScannerBase):
    """PHPStan scanner for PHP code quality."""

    @property
    def tool_name(self) -> str:
        return "phpstan"

    @property
    def display_name(self) -> str:
        return "PHPStan"

    @property
    def check_command(self) -> list[str]:
        return ['phpstan', '--version']

    @property
    def languages(self) -> list[str]:
        return ['php']

    def get_repo_config_paths(self, repo_path: Path) -> list[Path]:
        """Check for PHPStan config in repo."""
        return [
            repo_path / "phpstan.neon",
            repo_path / "phpstan.neon.dist",
            repo_path / "phpstan.dist.neon",
        ]

    def get_bundled_config_path(self, repo_path: Path) -> Path | None:
        """Use AppSec Galaxy bundled PHPStan config."""
        bundled = self.configs_dir / "phpstan.neon"
        return bundled if bundled.exists() else None

    def build_scan_command(self, repo_path: Path, output_file: Path, config_path: Path | None) -> list[str]:
        """Build PHPStan command."""
        cmd = ['phpstan', 'analyse']

        # Add config
        if config_path:
            cmd.extend(['-c', str(config_path)])

        # Output format
        cmd.extend(['--error-format=json', '--no-progress'])

        # Scan all PHP directories (common structure)
        php_dirs = []
        for common_dir in ['src', 'app', 'lib', 'includes', '.']:
            dir_path = repo_path / common_dir
            if dir_path.exists() and any(dir_path.rglob('*.php')):
                php_dirs.append(str(dir_path))

        if php_dirs:
            cmd.extend(php_dirs[:5])  # Limit to 5 directories
        else:
            # Fallback: scan current directory
            cmd.append(str(repo_path))

        return cmd

    def normalize_finding(self, raw_finding: dict, repo_path: Path) -> dict:
        """Convert PHPStan finding to AppSec Galaxy format."""
        file_path = Path(raw_finding.get('file', ''))
        try:
            relative_path = file_path.relative_to(repo_path)
        except ValueError:
            relative_path = file_path

        # Map PHPStan severity (level 0-9)
        # PHPStan doesn't have severity in error output, all are "errors"
        # We can infer from message or default to high
        severity = 'high'  # PHPStan errors are generally significant

        return {
            'tool': 'phpstan',
            'category': 'code_quality',
            'severity': severity,
            'check_id': raw_finding.get('identifier', 'phpstan-error'),
            'path': str(relative_path),
            'start': {
                'line': raw_finding.get('line', 0),
                'col': 0  # PHPStan doesn't provide column info
            },
            'end': {
                'line': raw_finding.get('line', 0),
                'col': 0
            },
            'extra': {
                'message': raw_finding.get('message', ''),
                'metadata': {
                    'category': 'code_quality',
                    'subcategory': 'type-safety',
                    'technology': ['php'],
                    'confidence': 'HIGH',
                    'tip': raw_finding.get('tip', '')
                }
            }
        }

    def extract_findings_from_output(self, raw_results: Any) -> list[dict]:
        """Extract findings from PHPStan JSON."""
        if isinstance(raw_results, dict):
            # PHPStan JSON format: {"totals": {...}, "files": {...}, "errors": [...]}

            # Check for file-based errors
            files_section = raw_results.get('files', {})
            findings = []

            for file_path, file_data in files_section.items():
                messages = file_data.get('messages', [])
                for msg in messages:
                    # Add file path to each message
                    msg['file'] = file_path
                    findings.append(msg)

            # Also check for top-level errors array (older PHPStan format)
            if 'errors' in raw_results:
                findings.extend(raw_results['errors'])

            return findings

        return []


# Export scanner function for main.py
def run_phpstan(repo_path: str, output_dir: str | None = None) -> list:
    """Run PHPStan quality scan."""
    scanner = PHPStanScanner()
    return scanner.run_scan(repo_path, output_dir)
