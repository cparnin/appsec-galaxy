"""
SwiftLint code quality scanner for Swift.

SwiftLint is the de facto standard Swift linter, enforcing style and conventions
based on the Swift API Design Guidelines.
"""

from pathlib import Path
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

    def parse_output(self, output_file: Path, repo_path: Path) -> list[dict]:
        """
        Parse SwiftLint output from stdout (captured in run_scan).

        SwiftLint outputs JSON to stdout when using --reporter json,
        so we override to read from the captured output instead of a file.
        """
        # SwiftLint writes to stdout, not a file, so we need to capture it differently
        # The base class run_scan captures stdout, but writes findings to output_file
        # We'll read the output file which should contain the JSON
        if not output_file.exists():
            self.logger.warning(f"{self.display_name} did not produce an output file")
            return []

        try:
            import json
            with open(output_file) as f:
                raw_results = json.load(f)

            findings = []
            results_list = self.extract_findings_from_output(raw_results)

            for raw_finding in results_list:
                try:
                    normalized = self.normalize_finding(raw_finding, repo_path)
                    findings.append(normalized)
                except Exception as e:
                    self.logger.debug(f"Failed to normalize finding: {e}")

            return findings

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse {self.display_name} JSON output: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Failed to parse {self.display_name} output: {e}")
            return []

    def run_scan(self, repo_path: str, output_dir: str = None) -> list[dict]:
        """
        Override run_scan to capture stdout since SwiftLint outputs JSON to stdout.
        """
        import subprocess
        import json

        try:
            # Check if tool is installed
            if not self.check_installed():
                print(f"⚠️  {self.display_name} not installed - skipping {'/'.join(self.languages)} code quality scan")
                self.logger.info(f"💡 Install {self.display_name} to enable code quality scanning")
                return []

            # Set up paths
            if output_dir is None:
                from appsec_galaxy.config import BASE_OUTPUT_DIR
                output_path = Path(BASE_OUTPUT_DIR) / "raw"
            else:
                output_path = Path(output_dir)

            output_path = output_path.resolve()
            output_path.mkdir(parents=True, exist_ok=True)
            output_file = output_path / f"{self.tool_name}.json"

            repo_path_obj = Path(repo_path).resolve()
            if not repo_path_obj.exists():
                self.logger.error(f"Repository path does not exist: {repo_path}")
                return []

            self.logger.debug(f"Starting {self.display_name} scan of {repo_path_obj}")

            # Find config
            config_path = self.find_config(repo_path_obj)

            # Build command
            cmd = self.build_scan_command(repo_path_obj, output_file, config_path)
            self.logger.debug(f"{self.display_name} command: {' '.join(cmd)}")

            # Delete old output file
            if output_file.exists():
                output_file.unlink()

            # Run scanner - SwiftLint outputs JSON to stdout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                shell=False,
                cwd=str(repo_path_obj)
            )

            self.logger.debug(f"{self.display_name} completed with return code: {result.returncode}")

            # SwiftLint returns 0 for success (even with warnings), non-zero for errors
            # We still want to process findings even if there are violations

            # Parse JSON from stdout
            if result.stdout.strip():
                try:
                    raw_results = json.loads(result.stdout)
                    # Save to output file for consistency
                    with open(output_file, 'w') as f:
                        json.dump(raw_results, f, indent=2)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse {self.display_name} JSON output: {e}")
                    if result.stderr:
                        self.logger.debug(f"stderr: {result.stderr[:500]}")
                    return []
            else:
                # No output means no findings
                raw_results = []

            # Normalize findings
            findings = []
            results_list = self.extract_findings_from_output(raw_results)

            for raw_finding in results_list:
                try:
                    normalized = self.normalize_finding(raw_finding, repo_path_obj)
                    findings.append(normalized)
                except Exception as e:
                    self.logger.debug(f"Failed to normalize finding: {e}")

            self.logger.info(f"✅ {self.display_name}: {len(findings)} code quality issues found")
            return findings

        except subprocess.TimeoutExpired:
            self.logger.error(f"{self.display_name} timed out after 5 minutes")
            return []
        except FileNotFoundError:
            self.logger.warning(f"{self.display_name} command not found")
            return []
        except Exception as e:
            self.logger.error(f"{self.display_name} scan failed: {e}")
            return []

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

    def extract_findings_from_output(self, raw_results: any) -> list[dict]:
        """Extract findings from SwiftLint JSON output."""
        # SwiftLint outputs an array of violations directly
        if isinstance(raw_results, list):
            return raw_results
        return []


# Export scanner function for main.py
def run_swiftlint(repo_path: str, output_dir: str = None) -> list:
    """Run SwiftLint quality scan."""
    scanner = SwiftLintScanner()
    return scanner.run_scan(repo_path, output_dir)
