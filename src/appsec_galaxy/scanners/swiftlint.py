"""
SwiftLint code quality scanner for Swift.

SwiftLint is the de facto standard Swift linter, enforcing style and conventions
based on the Swift API Design Guidelines.
"""

from pathlib import Path
from typing import Any
from .quality_scanner_base import QualityScannerBase


class SwiftLintScanner(QualityScannerBase):
    """SwiftLint scanner for Swift code quality."""

    @property
    def tool_name(self) -> str:
        return "swiftlint"

    @property
    def display_name(self) -> str:
        return "SwiftLint"

    @property
    def check_command(self) -> list[str]:
        return ['swiftlint', 'version']

    @property
    def languages(self) -> list[str]:
        return ['swift']

    def get_repo_config_paths(self, repo_path: Path) -> list[Path]:
        """Check for SwiftLint config in repo."""
        return [
            repo_path / ".swiftlint.yml",
            repo_path / ".swiftlint.yaml",
        ]

    def get_bundled_config_path(self, repo_path: Path) -> Path | None:
        """Use AppSec Galaxy bundled SwiftLint config."""
        bundled = self.configs_dir / "swiftlint.yml"
        return bundled if bundled.exists() else None

    def build_scan_command(self, repo_path: Path, output_file: Path, config_path: Path | None) -> list[str]:
        """Build SwiftLint command."""
        cmd = ['swiftlint', 'lint']

        # Add config
        if config_path:
            cmd.extend(['--config', str(config_path)])

        # Output format - JSON to file
        cmd.extend(['--reporter', 'json'])

        # Quiet mode to reduce noise
        cmd.append('--quiet')

        return cmd

    # SwiftLint prints its JSON report to stdout; the base class saves it to
    # the output file and parses it like every other linter. Any non-zero
    # exit is a tool failure (violations still exit 0 with --quiet).
    reads_stdout = True

    def is_fatal_exit(self, returncode: int) -> bool:
        return returncode != 0

    def normalize_finding(self, raw_finding: dict, repo_path: Path) -> dict:
        """Convert SwiftLint finding to AppSec Galaxy format."""
        file_path = Path(raw_finding.get('file', ''))
        try:
            relative_path = file_path.relative_to(repo_path)
        except ValueError:
            relative_path = file_path

        # Map SwiftLint severity
        severity_map = {
            'error': 'high',
            'warning': 'medium',
        }
        severity = severity_map.get(raw_finding.get('severity', 'warning').lower(), 'medium')

        line = raw_finding.get('line', 0)
        character = raw_finding.get('character', 0)

        # Determine subcategory based on rule type
        rule_id = raw_finding.get('rule_id', '')
        subcategory = self._get_subcategory(rule_id)

        return {
            'tool': 'swiftlint',
            'category': 'code_quality',
            'severity': severity,
            'check_id': rule_id,
            'path': str(relative_path),
            'start': {
                'line': line,
                'col': character
            },
            'end': {
                'line': line,
                'col': character
            },
            'extra': {
                'message': raw_finding.get('reason', ''),
                'metadata': {
                    'category': 'code_quality',
                    'subcategory': subcategory,
                    'technology': ['swift'],
                    'confidence': 'HIGH',
                    'rule_id': rule_id,
                    'type': raw_finding.get('type', '')
                }
            }
        }

    def _get_subcategory(self, rule_id: str) -> str:
        """Categorize SwiftLint rule into subcategory."""
        # Style rules
        style_rules = [
            'line_length', 'trailing_whitespace', 'vertical_whitespace',
            'opening_brace', 'closing_brace', 'colon', 'comma',
            'operator_usage_whitespace', 'return_arrow_whitespace',
            'statement_position', 'trailing_comma', 'trailing_newline',
            'trailing_semicolon', 'indentation_width'
        ]

        # Naming rules
        naming_rules = [
            'identifier_name', 'type_name', 'file_name',
            'generic_type_name', 'nesting', 'file_types_order'
        ]

        # Complexity/metrics rules
        complexity_rules = [
            'cyclomatic_complexity', 'function_body_length',
            'file_length', 'type_body_length', 'large_tuple',
            'function_parameter_count'
        ]

        # Lint/potential bugs
        lint_rules = [
            'force_cast', 'force_try', 'force_unwrapping',
            'implicitly_unwrapped_optional', 'fatal_error_message',
            'unused_closure_parameter', 'unused_enumerated',
            'unused_optional_binding', 'empty_count', 'empty_string',
            'redundant_nil_coalescing', 'redundant_optional_initialization',
            'redundant_void_return', 'redundant_discardable_let'
        ]

        # Performance rules
        performance_rules = [
            'empty_collection_literal', 'first_where',
            'contains_over_first_not_nil', 'contains_over_filter_count',
            'contains_over_filter_is_empty', 'flatmap_over_map_reduce',
            'reduce_boolean', 'reduce_into', 'sorted_first_last'
        ]

        if any(r in rule_id for r in style_rules):
            return 'code-style'
        elif any(r in rule_id for r in naming_rules):
            return 'naming-convention'
        elif any(r in rule_id for r in complexity_rules):
            return 'complexity'
        elif any(r in rule_id for r in lint_rules):
            return 'potential-bug'
        elif any(r in rule_id for r in performance_rules):
            return 'performance'
        else:
            return 'best-practice'

    def extract_findings_from_output(self, raw_results: Any) -> list[dict]:
        """Extract findings from SwiftLint JSON output."""
        # SwiftLint outputs an array of violations directly
        if isinstance(raw_results, list):
            return raw_results
        return []


# Export scanner function for main.py
def run_swiftlint(repo_path: str, output_dir: str | None = None) -> list:
    """Run SwiftLint quality scan."""
    scanner = SwiftLintScanner()
    return scanner.run_scan(repo_path, output_dir)
