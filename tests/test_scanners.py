"""
Scanner adapters: binary and path validation, language detection, the
gitleaks/semgrep/trivy parsers, the shared code-quality base, and the
canonical Finding shape every downstream consumer reads.
"""

import pytest
import json
import re
import subprocess
import shutil
import os
from pathlib import Path
from unittest.mock import Mock, patch
import sys
import tomllib


from appsec_galaxy.exceptions import (
    ScannerError, ValidationError, BinaryNotFoundError
)
from appsec_galaxy.scanners.validation import validate_binary_path, validate_repo_path, detect_languages
from appsec_galaxy.scanners.gitleaks import run_gitleaks
from appsec_galaxy.scanners.semgrep import run_semgrep, _categorize_finding
from appsec_galaxy.scanners.trivy import run_trivy_scan as run_trivy
from appsec_galaxy.exceptions import DependencyAnalysisError, RegistryLookupError


class TestExceptions:
    """Test custom exception classes."""

    def test_scanner_error_basic(self):
        """Test basic ScannerError creation."""
        error = ScannerError("Test error")
        assert str(error) == "Test error"
        assert error.scanner is None
        assert error.details == {}

    def test_scanner_error_with_details(self):
        """Test ScannerError with metadata."""
        details = {'path': '/test', 'code': 42}
        error = ScannerError("Error", scanner="semgrep", details=details)
        assert error.scanner == "semgrep"
        assert error.details['path'] == '/test'

    def test_validation_error_inheritance(self):
        """Test ValidationError inherits from ScannerError."""
        error = ValidationError("Invalid")
        assert isinstance(error, ScannerError)
        assert isinstance(error, Exception)

    def test_binary_not_found_error(self):
        """Test BinaryNotFoundError with install hints."""
        details = {'binary': 'semgrep', 'install_hint': 'pip install semgrep'}
        error = BinaryNotFoundError("Not found", scanner="semgrep", details=details)
        assert error.details['install_hint'] == 'pip install semgrep'

    def test_exception_chaining(self):
        """Test exception chaining with 'from' keyword."""
        original = ValueError("Original")
        with pytest.raises(ValidationError) as exc_info:
            try:
                raise original
            except ValueError as e:
                raise ValidationError("Wrapped") from e
        assert exc_info.value.__cause__ is original

class TestExceptionTypes:
    """Test new exception types."""

    def test_dependency_analysis_error(self):
        error = DependencyAnalysisError("Analysis failed", scanner="dependency_analyzer")
        assert isinstance(error, ScannerError)
        assert error.scanner == "dependency_analyzer"

    def test_registry_lookup_error(self):
        error = RegistryLookupError("Registry down", details={"registry": "npm"})
        assert isinstance(error, ScannerError)
        assert error.details["registry"] == "npm"

class TestBinaryValidation:
    """Test binary path validation with security checks."""

    def test_default_binary_path(self, mock_env_vars):
        """Test with default binary name."""
        result = validate_binary_path('SEMGREP_BIN', 'semgrep')
        assert result == 'semgrep'

    @pytest.mark.security
    def test_blocks_command_injection(self):
        """Test blocking dangerous characters: ; | & $ ` $(  ${"""
        dangerous = ['tool; rm -rf /', 'tool | cat', 'tool && bad', 'tool$(whoami)', 'tool`cmd`']
        for bad in dangerous:
            with patch.dict(os.environ, {'TEST_BIN': bad}):
                result = validate_binary_path('TEST_BIN', 'default')
                assert result is None, f"Should block: {bad}"

    @pytest.mark.security
    def test_blocks_null_bytes(self, monkeypatch):
        """Test null byte injection prevention."""
        def mock_getenv(key, default=None):
            return 'tool\x00malicious' if key == 'TEST_BIN' else default

        with patch('os.getenv', side_effect=mock_getenv):
            result = validate_binary_path('TEST_BIN', 'default')
            assert result is None

    def test_raises_on_error_flag(self):
        """Test raise_on_error=True raises exception."""
        with patch.dict(os.environ, {'TEST_BIN': 'tool; bad'}):
            with pytest.raises(BinaryNotFoundError):
                validate_binary_path('TEST_BIN', 'default', raise_on_error=True)

class TestRepoValidation:
    """Test repository path validation."""

    def test_valid_repo_path(self, mock_repo):
        """Test successful validation."""
        result = validate_repo_path(str(mock_repo))
        assert result is not None
        assert result.exists()
        assert result.is_dir()

    @pytest.mark.security
    def test_blocks_command_injection(self):
        """Test command injection prevention."""
        dangerous = ['/tmp; rm -rf /', '/tmp | cat', '/tmp && bad', '/tmp$(whoami)']
        for bad in dangerous:
            result = validate_repo_path(bad)
            assert result is None

    @pytest.mark.security
    def test_blocks_null_bytes(self):
        """Test null byte rejection."""
        result = validate_repo_path('/tmp\x00malicious')
        assert result is None

    def test_nonexistent_path(self):
        """Test validation fails for missing paths."""
        result = validate_repo_path('/nonexistent/path/12345')
        assert result is None

    def test_file_not_directory(self, temp_dir):
        """Test fails when path is file not directory."""
        file_path = temp_dir / "test.txt"
        file_path.write_text("not a dir")
        result = validate_repo_path(str(file_path))
        assert result is None

    def test_path_too_long(self):
        """Test extremely long paths are rejected."""
        long_path = '/tmp/' + 'a' * 5000
        result = validate_repo_path(long_path)
        assert result is None

class TestLanguageDetection:
    """Test programming language detection."""

    def test_python_detection(self, temp_dir):
        """Test Python file detection."""
        (temp_dir / "app.py").write_text("print('hello')")
        languages = detect_languages(temp_dir)
        assert 'python' in languages

    def test_javascript_detection(self, temp_dir):
        """Test JS/TS detection."""
        (temp_dir / "app.js").write_text("console.log('hi')")
        (temp_dir / "types.ts").write_text("interface User {}")
        languages = detect_languages(temp_dir)
        assert 'javascript' in languages or 'typescript' in languages

    def test_multiple_languages(self, temp_dir):
        """Test detection of multiple languages."""
        (temp_dir / "app.py").write_text("print('python')")
        (temp_dir / "app.js").write_text("console.log('js')")
        (temp_dir / "Main.java").write_text("public class Main {}")
        languages = detect_languages(temp_dir)
        assert len(languages) >= 2

    def test_ignores_node_modules(self, temp_dir):
        """Test that node_modules is ignored."""
        node_dir = temp_dir / "node_modules" / "pkg"
        node_dir.mkdir(parents=True)
        (node_dir / "index.js").write_text("module.exports = {}")
        (temp_dir / "app.py").write_text("print('hi')")

        languages = detect_languages(temp_dir)
        # Equality, not membership: with `in`, the test passes even if
        # node_modules stops being ignored.
        assert languages == {'python'}

    def test_empty_repo(self, temp_dir):
        """Test empty directory."""
        languages = detect_languages(temp_dir)
        assert isinstance(languages, set)
        assert len(languages) == 0

class TestGitleaks:
    """Test Gitleaks secrets scanner."""

    @patch('appsec_galaxy.scanners.gitleaks.subprocess.run')
    @patch('appsec_galaxy.scanners.gitleaks.validate_binary_path')
    @patch('appsec_galaxy.scanners.gitleaks.validate_repo_path')
    def test_nonzero_exit_is_an_error_not_findings(
        self, mock_validate_repo, mock_validate_binary, mock_subprocess,
        mock_repo, output_dir, sample_gitleaks_output
    ):
        """--exit-code 0 makes findings exit 0, so exit 1 is a failure and a
        partial report must not be parsed as a result."""
        mock_validate_binary.return_value = 'gitleaks'
        mock_validate_repo.return_value = mock_repo
        output_file = output_dir / "gitleaks.json"

        def mock_run(*args, **kwargs):
            output_file.write_text(json.dumps(sample_gitleaks_output))
            result = Mock()
            result.returncode = 1
            result.stdout, result.stderr = "", "failed to scan Git repository"
            return result

        mock_subprocess.side_effect = mock_run
        assert run_gitleaks(str(mock_repo), output_dir) == []

    @patch('appsec_galaxy.scanners.gitleaks.subprocess.run')
    @patch('appsec_galaxy.scanners.gitleaks.validate_binary_path')
    @patch('appsec_galaxy.scanners.gitleaks.validate_repo_path')
    def test_plain_directory_gets_no_git_flag(
        self, mock_validate_repo, mock_validate_binary, mock_subprocess, tmp_path, output_dir
    ):
        mock_validate_binary.return_value = 'gitleaks'
        mock_validate_repo.return_value = tmp_path  # no .git inside
        result = Mock(returncode=0, stdout="", stderr="")
        mock_subprocess.return_value = result
        run_gitleaks(str(tmp_path), output_dir)
        assert '--no-git' in mock_subprocess.call_args[0][0]

    @patch('appsec_galaxy.scanners.gitleaks.subprocess.run')
    @patch('appsec_galaxy.scanners.gitleaks.validate_binary_path')
    @patch('appsec_galaxy.scanners.gitleaks.validate_repo_path')
    def test_success_with_findings(
        self, mock_validate_repo, mock_validate_binary, mock_subprocess,
        mock_repo, output_dir, sample_gitleaks_output
    ):
        """Test successful scan with secrets found."""
        mock_validate_binary.return_value = 'gitleaks'
        mock_validate_repo.return_value = mock_repo
        output_file = output_dir / "gitleaks.json"

        def mock_run(*args, **kwargs):
            output_file.write_text(json.dumps(sample_gitleaks_output))
            result = Mock()
            result.returncode = 0  # --exit-code 0: findings never change the exit code
            result.stdout = result.stderr = ""
            return result

        mock_subprocess.side_effect = mock_run
        results = run_gitleaks(str(mock_repo), output_dir)

        assert [r['RuleID'] for r in results] == [
            r['RuleID'] for r in sample_gitleaks_output]
        assert all(f['category'] == 'security' and f['tool'] == 'gitleaks' for f in results)
        # The secret value never crosses the Finding boundary.
        assert all('Secret' not in f and 'Match' not in f for f in results)

    @patch('appsec_galaxy.scanners.gitleaks.subprocess.run')
    @patch('appsec_galaxy.scanners.gitleaks.validate_binary_path')
    @patch('appsec_galaxy.scanners.gitleaks.validate_repo_path')
    def test_no_secrets_found(
        self, mock_validate_repo, mock_validate_binary, mock_subprocess,
        mock_repo, output_dir
    ):
        """Test scan with no secrets."""
        mock_validate_binary.return_value = 'gitleaks'
        mock_validate_repo.return_value = mock_repo
        output_file = output_dir / "gitleaks.json"

        def mock_run(*args, **kwargs):
            output_file.write_text("")
            result = Mock()
            result.returncode = 0
            result.stdout = result.stderr = ""
            return result

        mock_subprocess.side_effect = mock_run
        results = run_gitleaks(str(mock_repo), output_dir)
        assert results == []

    @patch('appsec_galaxy.scanners.gitleaks.validate_binary_path')
    def test_binary_not_found(self, mock_validate_binary, mock_repo):
        """Test when gitleaks binary is missing."""
        mock_validate_binary.return_value = None
        results = run_gitleaks(str(mock_repo))
        assert results == []

    @patch('appsec_galaxy.scanners.gitleaks.subprocess.run')
    @patch('appsec_galaxy.scanners.gitleaks.validate_binary_path')
    @patch('appsec_galaxy.scanners.gitleaks.validate_repo_path')
    def test_timeout_handling(
        self, mock_validate_repo, mock_validate_binary, mock_subprocess, mock_repo
    ):
        """Test timeout error handling."""
        mock_validate_binary.return_value = 'gitleaks'
        mock_validate_repo.return_value = mock_repo
        mock_subprocess.side_effect = subprocess.TimeoutExpired('gitleaks', 120)

        results = run_gitleaks(str(mock_repo))
        assert results == []

class TestSecretConfidence:
    """Offline secret confidence classification (scanners/gitleaks.py).

    Pure functions: no network, and the reason string must never echo
    the secret value."""

    def test_entropy_bounds(self):
        from appsec_galaxy.scanners.gitleaks import shannon_entropy
        assert shannon_entropy('') == 0.0
        assert shannon_entropy('aaaa') == 0.0
        assert shannon_entropy('ab') == 1.0
        assert shannon_entropy('gh0stP3pper!xQz47Lm') > 3.5

    def test_placeholders_are_low(self):
        from appsec_galaxy.scanners.gitleaks import classify_secret_confidence
        for value in ('your-api-key-here', 'sk-EXAMPLE-key', 'CHANGEME',
                      '<YOUR_TOKEN>', '${API_KEY}', '{{ secret }}',
                      'test_password_123', 'xxxxxxxxxxxx', 'REDACTED'):
            confidence, reason = classify_secret_confidence(value)
            assert confidence == 'low', f'{value!r} should be low, got {confidence}'

    def test_degenerate_values_are_low(self):
        from appsec_galaxy.scanners.gitleaks import classify_secret_confidence
        assert classify_secret_confidence('')[0] == 'low'
        assert classify_secret_confidence('zzzzzzzzzzzzzzzz')[0] == 'low'  # one repeated char
        assert classify_secret_confidence('hunter2')[0] == 'low'           # too short

    def test_real_looking_secret_is_high(self):
        from appsec_galaxy.scanners.gitleaks import classify_secret_confidence
        confidence, reason = classify_secret_confidence('ghp_x9K2mQ8vL4nR7tY1wE3uI6oP0aS5dF8g')
        assert confidence == 'high'
        assert 'entropy' in reason

    def test_reason_never_contains_secret(self):
        from appsec_galaxy.scanners.gitleaks import classify_secret_confidence
        secret = 'ghp_x9K2mQ8vL4nR7tY1wE3uI6oP0aS5dF8g'
        for value in (secret, 'your-key-here', 'aaaaaaaaaa'):
            _, reason = classify_secret_confidence(value)
            assert value not in reason

    @patch('appsec_galaxy.scanners.gitleaks.subprocess.run')
    @patch('appsec_galaxy.scanners.gitleaks.validate_binary_path')
    @patch('appsec_galaxy.scanners.gitleaks.validate_repo_path')
    def test_run_gitleaks_attaches_confidence(
        self, mock_validate_repo, mock_validate_binary, mock_subprocess,
        mock_repo, output_dir, sample_gitleaks_output
    ):
        mock_validate_binary.return_value = 'gitleaks'
        mock_validate_repo.return_value = mock_repo
        output_file = output_dir / "gitleaks.json"

        def mock_run(*args, **kwargs):
            output_file.write_text(json.dumps(sample_gitleaks_output))
            result = Mock()
            result.returncode = 0  # --exit-code 0: findings never change the exit code
            result.stdout = result.stderr = ""
            return result

        mock_subprocess.side_effect = mock_run
        results = run_gitleaks(str(mock_repo), output_dir)
        assert results and 'confidence' in results[0]
        # fixture secret is sk-1234567890abcdef: sequential digits -> low
        assert results[0]['confidence'] == 'low'
        # The plaintext secret must not survive the Finding boundary: not in
        # the payload, and not echoed back through the confidence reason.
        fixture_secret = sample_gitleaks_output[0]['Secret']
        assert 'Secret' not in results[0]
        assert 'Match' not in results[0]
        assert fixture_secret not in json.dumps(results[0])

    def test_html_sorts_low_confidence_last(self, tmp_path):
        from appsec_galaxy.reporting.html import generate_html_report
        findings = [
            {'tool': 'gitleaks', 'RuleID': 'k1', 'File': 'a.py', 'StartLine': 1,
             'Description': 'placeholder secret', 'category': 'security',
             'confidence': 'low', 'confidence_reason': 'placeholder or test-fixture pattern'},
            {'tool': 'gitleaks', 'RuleID': 'k2', 'File': 'b.py', 'StartLine': 2,
             'Description': 'real looking secret', 'category': 'security',
             'confidence': 'high', 'confidence_reason': 'high entropy (4.1 bits/char)'},
        ]
        out = tmp_path / 'out'
        out.mkdir()
        generate_html_report(findings, '', str(out), '/repo', {'python'})
        html_out = (out / 'report.html').read_text()
        assert 'Confidence:' in html_out
        assert html_out.index('real looking secret') < html_out.index('placeholder secret')

class TestSemgrep:
    """Test Semgrep SAST scanner."""

    @pytest.mark.parametrize("check_id", [
        'javascript.security.sqli',
        'python.security.injection',
        'javascript.best-practice.unused',
        'python.maintainability.complexity',
    ])
    def test_categorize_finding_always_security(self, check_id):
        """Semgrep is security-only; all findings categorize as security."""
        assert _categorize_finding(check_id) == 'security'

    def test_security_takes_priority(self):
        """Test security patterns prioritized over code quality."""
        result = _categorize_finding('javascript.security.performance.crypto')
        assert result == 'security'

    def test_unknown_defaults_security(self):
        """Test unknown patterns default to security (conservative)."""
        result = _categorize_finding('unknown.rule.pattern')
        assert result == 'security'

    @patch('appsec_galaxy.scanners.semgrep.subprocess.run')
    @patch('appsec_galaxy.scanners.semgrep.validate_repo_path')
    def test_scan_with_findings(
        self, mock_validate_repo, mock_subprocess,
        mock_repo, output_dir, sample_semgrep_output
    ):
        """Test successful Semgrep scan."""
        mock_validate_repo.return_value = mock_repo

        def create_output_file(*args, **kwargs):
            output_file = output_dir / "semgrep.json"
            output_file.write_text(json.dumps(sample_semgrep_output))
            result = Mock()
            result.returncode = 1
            result.stdout = json.dumps(sample_semgrep_output)
            result.stderr = ""
            return result

        mock_subprocess.side_effect = create_output_file

        results = run_semgrep(str(mock_repo), str(output_dir))
        assert isinstance(results, list)
        assert len(results) > 0

    @patch('appsec_galaxy.scanners.semgrep.subprocess.run')
    @patch('appsec_galaxy.scanners.semgrep.validate_repo_path')
    def test_invalid_repo(self, mock_validate_repo, mock_subprocess):
        """Test with invalid repo path."""
        mock_validate_repo.return_value = None
        results = run_semgrep('/invalid/path')
        assert results == []

    @patch('appsec_galaxy.scanners.semgrep.subprocess.run')
    @patch('appsec_galaxy.scanners.semgrep.validate_repo_path')
    def test_command_disables_metrics(
        self, mock_validate_repo, mock_subprocess, mock_repo, output_dir
    ):
        """Registry-fetching configs phone scan telemetry home unless
        --metrics=off; a tool scanning private/client code must not send it."""
        mock_validate_repo.return_value = mock_repo

        result = Mock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""
        mock_subprocess.return_value = result

        run_semgrep(str(mock_repo), str(output_dir))
        cmd = mock_subprocess.call_args_list[0][0][0]
        assert "--metrics=off" in cmd

    @patch('appsec_galaxy.scanners.semgrep.subprocess.run')
    @patch('appsec_galaxy.scanners.semgrep.validate_repo_path')
    def test_command_uses_pinned_ruleset_by_default(
        self, mock_validate_repo, mock_subprocess, mock_repo, output_dir, monkeypatch
    ):
        """Rulesets are pinned (p/default), not 'auto': the same code must
        produce the same findings across CLI, CI, and time."""
        monkeypatch.delenv('APPSEC_SEMGREP_CONFIG', raising=False)
        mock_validate_repo.return_value = mock_repo
        mock_subprocess.return_value = Mock(returncode=0, stdout="", stderr="")

        run_semgrep(str(mock_repo), str(output_dir))
        cmd = mock_subprocess.call_args_list[0][0][0]
        configs = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == '--config']
        assert configs == ['p/default']

    @patch('appsec_galaxy.scanners.semgrep.subprocess.run')
    @patch('appsec_galaxy.scanners.semgrep.validate_repo_path')
    def test_command_honors_ruleset_override(
        self, mock_validate_repo, mock_subprocess, mock_repo, output_dir, monkeypatch
    ):
        """APPSEC_SEMGREP_CONFIG accepts a comma-separated ruleset list."""
        monkeypatch.setenv('APPSEC_SEMGREP_CONFIG', 'p/ci, p/xss')
        mock_validate_repo.return_value = mock_repo
        mock_subprocess.return_value = Mock(returncode=0, stdout="", stderr="")

        run_semgrep(str(mock_repo), str(output_dir))
        cmd = mock_subprocess.call_args_list[0][0][0]
        configs = [cmd[i + 1] for i, arg in enumerate(cmd) if arg == '--config']
        assert configs == ['p/ci', 'p/xss']

class TestTrivy:
    """Test Trivy dependency scanner."""

    @patch('appsec_galaxy.scanners.trivy.subprocess.run')
    @patch('appsec_galaxy.scanners.trivy.validate_repo_path')
    def test_scan_with_vulnerabilities(
        self, mock_validate_repo, mock_subprocess,
        mock_repo, output_dir, sample_trivy_output
    ):
        """Test successful Trivy scan with CVEs."""
        mock_validate_repo.return_value = mock_repo

        def create_output_file(*args, **kwargs):
            output_file = output_dir / "trivy-sca.json"
            output_file.write_text(json.dumps(sample_trivy_output))
            result = Mock()
            result.returncode = 0
            result.stdout = json.dumps(sample_trivy_output)
            result.stderr = ""
            return result

        mock_subprocess.side_effect = create_output_file

        results = run_trivy(str(mock_repo), str(output_dir))
        assert isinstance(results, list)
        assert len(results) > 0

    @patch('appsec_galaxy.scanners.trivy.subprocess.run')
    @patch('appsec_galaxy.scanners.trivy.validate_repo_path')
    def test_no_vulnerabilities(
        self, mock_validate_repo, mock_subprocess, mock_repo, output_dir
    ):
        """Test scan with clean dependencies."""
        mock_validate_repo.return_value = mock_repo

        result = Mock()
        result.returncode = 0
        result.stdout = json.dumps({"Results": []})
        result.stderr = ""
        mock_subprocess.return_value = result

        results = run_trivy(str(mock_repo), str(output_dir))
        assert results == []

    @patch('appsec_galaxy.scanners.trivy.validate_repo_path')
    def test_invalid_repo(self, mock_validate_repo):
        """Test with invalid repo path."""
        mock_validate_repo.return_value = None
        results = run_trivy('/invalid/path')
        assert results == []

    @patch('appsec_galaxy.scanners.trivy.subprocess.run')
    @patch('appsec_galaxy.scanners.trivy.validate_repo_path')
    def test_command_includes_misconfig_scanner(
        self, mock_validate_repo, mock_subprocess, mock_repo, output_dir
    ):
        """Root scan must request the configured scanner set (vuln,misconfig)."""
        mock_validate_repo.return_value = mock_repo

        result = Mock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""
        mock_subprocess.return_value = result

        run_trivy(str(mock_repo), str(output_dir))
        cmd = mock_subprocess.call_args_list[0][0][0]
        assert cmd[cmd.index("--scanners") + 1] == "vuln,misconfig"

    @patch('appsec_galaxy.scanners.trivy.subprocess.run')
    @patch('appsec_galaxy.scanners.trivy.validate_repo_path')
    def test_misconfigurations_normalized(
        self, mock_validate_repo, mock_subprocess,
        mock_repo, output_dir, sample_trivy_misconfig_output
    ):
        """Misconfigurations arrays parse into canonical findings with file/line."""
        mock_validate_repo.return_value = mock_repo

        def create_output_file(*args, **kwargs):
            output_file = output_dir / "trivy-sca.json"
            output_file.write_text(json.dumps(sample_trivy_misconfig_output))
            result = Mock()
            result.returncode = 0
            result.stdout = ""
            result.stderr = ""
            return result

        mock_subprocess.side_effect = create_output_file

        results = run_trivy(str(mock_repo), str(output_dir))
        assert len(results) == 1
        f = results[0]
        assert f['tool'] == 'trivy'
        assert f['finding_type'] == 'misconfiguration'
        assert f['path'] == 'Dockerfile'
        assert f['line'] == 1
        assert f['severity'] == 'high'
        assert f['vulnerability_id'] == 'DS002'
        assert 'root' in f['description']
        assert f['resolution'].startswith("Add 'USER")
        # Must never look upgradeable to the dependency auto-fixer
        assert 'fixed_version' not in f
        assert 'pkg_name' not in f

    @patch('appsec_galaxy.scanners.trivy.subprocess.run')
    @patch('appsec_galaxy.scanners.trivy.validate_repo_path')
    def test_vendor_fallback_preserves_misconfigs(
        self, mock_validate_repo, mock_subprocess,
        mock_repo, output_dir, sample_trivy_misconfig_output, sample_trivy_output
    ):
        """A misconfig-only root result must still trigger the vendor vuln
        fallback, and the fallback must merge (not replace) root results."""
        mock_validate_repo.return_value = mock_repo
        (mock_repo / 'node_modules').mkdir()

        def run_side_effect(cmd, **kwargs):
            out = Path(cmd[cmd.index("--output") + 1])
            if 'node_modules' in cmd[-1]:
                out.write_text(json.dumps(sample_trivy_output))
            else:
                out.write_text(json.dumps(sample_trivy_misconfig_output))
            result = Mock()
            result.returncode = 0
            result.stdout = ""
            result.stderr = ""
            return result

        mock_subprocess.side_effect = run_side_effect

        results = run_trivy(str(mock_repo), str(output_dir))
        tools = {f.get('finding_type', 'vulnerability') for f in results}
        assert tools == {'misconfiguration', 'vulnerability'}
        assert len(results) == 2

class TestQualityScannerBase:
    """Regressions from the full-app review: golangci-lint and swiftlint print
    JSON to stdout that the base class discarded (always 0 findings), repo
    configs were preferred over bundled ones (linter configs execute code),
    and Checkstyle's violation-count exit code was treated as a crash."""

    def _scanner(self, tmp_path, **overrides):
        from appsec_galaxy.scanners.quality_scanner_base import QualityScannerBase

        class Fake(QualityScannerBase):
            tool_name = 'fake'
            display_name = 'Fake'
            check_command = ['fake', '--version']
            languages = ['x']

            def get_repo_config_paths(self, repo_path):
                return [repo_path / '.fakerc']

            def get_bundled_config_path(self, repo_path):
                return overrides.get('bundled')

            def build_scan_command(self, repo_path, output_file, config_path):
                self.seen_config = config_path
                return ['fake']

            def normalize_finding(self, raw, repo_path):
                return {'tool': 'fake', 'category': 'code_quality', 'severity': 'medium',
                        'check_id': raw['id'], 'path': 'a', 'extra': {'message': ''}}

        s = Fake()
        for k, v in overrides.items():
            if k != 'bundled':
                setattr(s, k, v)
        s.check_installed = lambda: True
        return s

    def _run(self, scanner, monkeypatch, tmp_path, returncode=0, stdout=''):
        import subprocess as sp
        monkeypatch.setattr(sp, 'run', lambda *a, **k: Mock(returncode=returncode, stdout=stdout, stderr=''))
        repo = tmp_path / 'repo'
        repo.mkdir(exist_ok=True)
        return scanner.run_scan(str(repo), str(tmp_path / 'out'))

    def test_stdout_json_is_captured_when_declared(self, monkeypatch, tmp_path):
        s = self._scanner(tmp_path, reads_stdout=True)
        findings = self._run(s, monkeypatch, tmp_path, stdout='[{"id": "r1"}, {"id": "r2"}]')
        assert [f['check_id'] for f in findings] == ['r1', 'r2']
        assert (tmp_path / 'out' / 'fake.json').exists()

    def test_bundled_config_wins_over_repo_config(self, monkeypatch, tmp_path):
        bundled = tmp_path / 'bundled.cfg'
        bundled.write_text('')
        (tmp_path / 'repo').mkdir()
        (tmp_path / 'repo' / '.fakerc').write_text('init-hook=evil')
        s = self._scanner(tmp_path, bundled=bundled)
        self._run(s, monkeypatch, tmp_path)
        assert s.seen_config == bundled

    def test_repo_config_only_when_nothing_is_bundled(self, monkeypatch, tmp_path):
        (tmp_path / 'repo').mkdir()
        (tmp_path / 'repo' / '.fakerc').write_text('')
        s = self._scanner(tmp_path)
        self._run(s, monkeypatch, tmp_path)
        assert s.seen_config == tmp_path / 'repo' / '.fakerc'

    def test_fatal_exit_without_output_yields_nothing(self, monkeypatch, tmp_path):
        s = self._scanner(tmp_path, reads_stdout=True)
        assert self._run(s, monkeypatch, tmp_path, returncode=2, stdout='') == []

    def test_checkstyle_exit_code_is_a_count_not_a_failure(self):
        from appsec_galaxy.scanners.checkstyle import CheckstyleScanner
        assert CheckstyleScanner().is_fatal_exit(7) is False

    def test_swiftlint_and_golangci_read_stdout(self):
        from appsec_galaxy.scanners.swiftlint import SwiftLintScanner
        from appsec_galaxy.scanners.golangci_lint import GolangCILintScanner
        assert SwiftLintScanner.reads_stdout and GolangCILintScanner.reads_stdout

    def test_pylint_never_loads_repo_rcfile(self, monkeypatch, tmp_path):
        import subprocess as sp
        from appsec_galaxy.scanners import pylint as pl
        calls = []
        monkeypatch.setattr(sp, 'run', lambda cmd, **k: calls.append(cmd) or Mock(returncode=0, stdout='[]', stderr=''))
        monkeypatch.setattr(pl, 'check_pylint_installed', lambda: True, raising=False)
        (tmp_path / 'a.py').write_text('x = 1\n')
        pl.run_pylint(str(tmp_path), str(tmp_path / 'out'))
        pylint_cmd = next((c for c in calls if c and c[0] == 'pylint'), None)
        assert pylint_cmd is not None
        assert any(a.startswith('--rcfile=') for a in pylint_cmd)

    def test_eslint_uses_bundled_config_and_ignores_repo_config(self, monkeypatch, tmp_path):
        import subprocess as sp
        from appsec_galaxy.scanners import eslint as es
        calls = []

        def fake_run(cmd, **k):
            calls.append(cmd)
            return Mock(returncode=0, stdout='v9.30.0\n', stderr='')

        monkeypatch.setattr(sp, 'run', fake_run)
        monkeypatch.setattr(es, 'check_eslint_installed', lambda: True)
        (tmp_path / 'eslint.config.js').write_text('process.exit(1)')
        (tmp_path / 'a.js').write_text('var x = 1\n')
        es.run_eslint(str(tmp_path), str(tmp_path / 'out'))
        eslint_cmd = next(c for c in calls if c[0] == 'eslint' and c[1] != '--version')
        assert '--no-config-lookup' in eslint_cmd
        assert '--ext' not in eslint_cmd
        assert str(tmp_path / 'eslint.config.js') not in eslint_cmd

class TestFinding:
    """Canonical Finding dataclass (src/finding.py) - the scanner output boundary."""

    def test_from_semgrep_dict_shape_backwards_compatible(self):
        """to_dict() must equal the pre-dataclass semgrep augmentation."""
        from appsec_galaxy.finding import Finding
        raw = {
            'check_id': 'python.lang.security.sqli',
            'path': 'app/db.py',
            'start': {'line': 42},
            'extra': {'message': 'SQL injection risk', 'severity': 'ERROR'},
        }
        d = Finding.from_semgrep(raw, 'high', 'security').to_dict()
        expected = {**raw, 'severity': 'high', 'tool': 'semgrep', 'category': 'security'}
        assert d == expected

    def test_from_semgrep_canonical_fields(self):
        from appsec_galaxy.finding import Finding
        raw = {'path': 'a.py', 'start': {'line': 7}, 'extra': {'message': 'xss'}}
        f = Finding.from_semgrep(raw, 'critical', 'security')
        assert (f.tool, f.severity, f.path, f.line, f.message) == \
            ('semgrep', 'critical', 'a.py', 7, 'xss')

    def test_from_gitleaks_preserves_raw_keys_but_strips_secret_value(self):
        from appsec_galaxy.finding import Finding
        raw = {'Description': 'AWS key', 'File': 'config.py', 'StartLine': 3,
               'Secret': 'AKIA-fixture-value', 'Match': 'key = AKIA-fixture-value'}
        d = Finding.from_gitleaks(raw).to_dict()
        # Metadata keys survive; the plaintext credential does not.
        for k in ('Description', 'File', 'StartLine'):
            assert d[k] == raw[k]
        assert 'Secret' not in d
        assert 'Match' not in d
        assert 'AKIA-fixture-value' not in json.dumps(d)
        assert d['category'] == 'security'
        assert d['tool'] == 'gitleaks'

    def test_from_gitleaks_no_invented_severity(self):
        """Secrets have no scanner severity; payload must not contain one."""
        from appsec_galaxy.finding import Finding
        f = Finding.from_gitleaks({'Description': 'x', 'File': 'f', 'StartLine': 1})
        assert f.severity is None
        assert 'severity' not in f.to_dict()

    def test_from_trivy_dict_shape_backwards_compatible(self):
        """to_dict() must equal the pre-dataclass trivy standardized dict."""
        from appsec_galaxy.finding import Finding
        vuln = {
            'PkgName': 'lodash', 'InstalledVersion': '4.17.15', 'FixedVersion': '4.17.21',
            'VulnerabilityID': 'CVE-2021-23337', 'Title': 'Command injection',
            'Severity': 'HIGH', 'References': ['https://example.com'],
        }
        d = Finding.from_trivy(vuln, 'package-lock.json').to_dict()
        assert d == {
            'path': 'package-lock.json',
            'line': 1,
            'description': 'lodash 4.17.15: Command injection',
            'severity': 'high',
            'vulnerability_id': 'CVE-2021-23337',
            'pkg_name': 'lodash',
            'installed_version': '4.17.15',
            'fixed_version': '4.17.21',
            'references': ['https://example.com'],
            'tool': 'trivy',
            'category': 'security',
        }

    def test_from_trivy_missing_fields_defaults(self):
        from appsec_galaxy.finding import Finding
        d = Finding.from_trivy({}, 'requirements.txt').to_dict()
        assert d['severity'] == 'unknown'
        assert d['pkg_name'] == ''
        assert d['fixed_version'] == ''

    def test_from_trivy_misconfig_dict_shape(self):
        from appsec_galaxy.finding import Finding
        misconf = {
            'ID': 'DS002', 'Title': "Image user should not be 'root'",
            'Description': 'Root user risk', 'Resolution': 'Add USER line',
            'Severity': 'HIGH', 'References': ['https://avd.aquasec.com/misconfig/ds002'],
            'CauseMetadata': {'StartLine': 3, 'EndLine': 12},
        }
        d = Finding.from_trivy_misconfig(misconf, 'Dockerfile').to_dict()
        assert d == {
            'path': 'Dockerfile',
            'line': 3,
            'description': "DS002: Image user should not be 'root'",
            'severity': 'high',
            'vulnerability_id': 'DS002',
            'misconfig_description': 'Root user risk',
            'resolution': 'Add USER line',
            'references': ['https://avd.aquasec.com/misconfig/ds002'],
            'finding_type': 'misconfiguration',
            'tool': 'trivy',
            'category': 'security',
        }

    def test_from_trivy_misconfig_missing_fields_defaults(self):
        from appsec_galaxy.finding import Finding
        d = Finding.from_trivy_misconfig({}, 'main.tf').to_dict()
        assert d['severity'] == 'unknown'
        assert d['line'] == 1
        assert d['description'] == 'Misconfiguration'
        assert 'fixed_version' not in d
        assert 'pkg_name' not in d

    def test_to_dict_returns_copy(self):
        """Mutating the emitted dict must not corrupt the Finding."""
        from appsec_galaxy.finding import Finding
        f = Finding.from_gitleaks({'Description': 'x', 'File': 'f', 'StartLine': 1})
        d = f.to_dict()
        d['tool'] = 'tampered'
        assert f.to_dict()['tool'] == 'gitleaks'

class TestFindingHelpers:
    """Field extraction helpers shared by SARIF/filters/history."""

    def test_semgrep_shape(self):
        from appsec_galaxy.finding import finding_line, finding_message, finding_path, finding_rule_id, finding_severity
        f = {'tool': 'semgrep', 'check_id': 'sqli', 'path': 'a.py',
             'start': {'line': 12}, 'extra': {'message': 'bad'}, 'severity': 'high'}
        assert finding_path(f) == 'a.py'
        assert finding_line(f) == 12
        assert finding_rule_id(f) == 'sqli'
        assert finding_message(f) == 'bad'
        assert finding_severity(f) == 'high'

    def test_gitleaks_shape(self):
        from appsec_galaxy.finding import finding_line, finding_path, finding_rule_id, finding_severity
        f = {'tool': 'gitleaks', 'RuleID': 'aws-key', 'File': 'cfg.py', 'StartLine': 3}
        assert finding_path(f) == 'cfg.py'
        assert finding_line(f) == 3
        assert finding_rule_id(f) == 'aws-key'
        assert finding_severity(f) == 'critical'  # secrets default critical

    def test_trivy_shape(self):
        from appsec_galaxy.finding import finding_line, finding_path, finding_rule_id
        f = {'tool': 'trivy', 'vulnerability_id': 'CVE-2021-1', 'path': 'package-lock.json', 'line': 1}
        assert finding_path(f) == 'package-lock.json'
        assert finding_rule_id(f) == 'CVE-2021-1'
        assert finding_line(f) == 1

    def test_empty_finding_defaults(self):
        from appsec_galaxy.finding import finding_line, finding_path, finding_rule_id, finding_severity
        assert finding_path({}) == ''
        assert finding_line({}) == 1
        assert finding_rule_id({}) == 'unknown'
        assert finding_severity({}) == 'medium'

class TestScanPathContainment:
    """Confining scan targets to allowed roots (validation.path_within_roots
    plus the MCP and web wiring). Blocks arbitrary local-directory scanning
    and the source disclosure it enables."""

    def test_within_root_true(self, tmp_path):
        from appsec_galaxy.scanners.validation import path_within_roots
        (tmp_path / 'repo').mkdir()
        assert path_within_roots(str(tmp_path / 'repo'), [str(tmp_path)]) is True

    def test_root_itself_allowed(self, tmp_path):
        from appsec_galaxy.scanners.validation import path_within_roots
        assert path_within_roots(str(tmp_path), [str(tmp_path)]) is True

    def test_outside_root_false(self, tmp_path):
        from appsec_galaxy.scanners.validation import path_within_roots
        a = tmp_path / 'allowed'
        a.mkdir()
        b = tmp_path / 'secret'
        b.mkdir()
        assert path_within_roots(str(b), [str(a)]) is False

    def test_sibling_prefix_not_confused(self, tmp_path):
        """/allowed must not match /allowed-evil by string prefix."""
        from appsec_galaxy.scanners.validation import path_within_roots
        (tmp_path / 'allowed').mkdir()
        evil = tmp_path / 'allowed-evil'
        evil.mkdir()
        assert path_within_roots(str(evil), [str(tmp_path / 'allowed')]) is False

    def test_symlink_escape_blocked(self, tmp_path):
        from appsec_galaxy.scanners.validation import path_within_roots
        allowed = tmp_path / 'allowed'
        allowed.mkdir()
        outside = tmp_path / 'outside'
        outside.mkdir()
        link = allowed / 'escape'
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable")
        # realpath resolves the symlink out of the allowed root
        assert path_within_roots(str(link), [str(allowed)]) is False

    def test_empty_roots_deny_all(self, tmp_path):
        from appsec_galaxy.scanners.validation import path_within_roots
        assert path_within_roots(str(tmp_path), []) is False

    def test_web_validator_enforces_allowlist(self, tmp_path, monkeypatch):
        from appsec_galaxy.main import validate_repo_path
        allowed = tmp_path / 'allowed'
        allowed.mkdir()
        (allowed / '.git').mkdir()
        outside = tmp_path / 'outside'
        outside.mkdir()
        (outside / '.git').mkdir()
        monkeypatch.setenv('APPSEC_ALLOWED_SCAN_ROOTS', str(allowed))
        # inside is accepted
        assert validate_repo_path(str(allowed)).name == 'allowed'
        # outside is rejected
        with pytest.raises(ValueError, match='ALLOWED_SCAN_ROOTS'):
            validate_repo_path(str(outside))

    def test_mcp_rejects_parent_traversal(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'mcp'))
        if 'appsec_galaxy_mcp_server' in sys.modules:
            del sys.modules['appsec_galaxy_mcp_server']
        import appsec_galaxy_mcp_server as m
        with pytest.raises(ValueError, match="\\.\\."):
            m._validate_repo_arg('../../etc')

    def test_mcp_find_repo_confines_absolute_path(self, tmp_path, monkeypatch):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'mcp'))
        if 'appsec_galaxy_mcp_server' in sys.modules:
            del sys.modules['appsec_galaxy_mcp_server']
        import appsec_galaxy_mcp_server as m
        allowed = tmp_path / 'ok'
        allowed.mkdir()
        outside = tmp_path / 'nope'
        outside.mkdir()
        monkeypatch.setenv('APPSEC_MCP_ALLOWED_ROOTS', str(allowed))
        monkeypatch.setenv('APPSEC_GALAXY_PATH', str(Path(__file__).resolve().parent.parent))
        core = m.AppSecGalaxyMCPCore()
        assert core.find_repo(str(allowed)) == str(allowed)
        with pytest.raises(ValueError, match='allowed scan roots'):
            core.find_repo(str(outside))

class TestSeverityAlignment:
    """Semgrep severity mapping must be identical across the scanner
    pipeline and the MCP server. Regression: the MCP server inflated
    severities one level (ERROR reported as critical)."""

    def test_mcp_map_matches_scanner_semantics(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'mcp'))
        if 'appsec_galaxy_mcp_server' in sys.modules:
            del sys.modules['appsec_galaxy_mcp_server']
        import appsec_galaxy_mcp_server
        expected = {
            'CRITICAL': 'critical',
            'ERROR': 'high',
            'WARNING': 'medium',
            'INFO': 'low',
        }
        for semgrep_name, normalized in expected.items():
            assert appsec_galaxy_mcp_server._SEMGREP_SEVERITY_MAP[semgrep_name] == normalized, \
                f"MCP maps {semgrep_name} to {appsec_galaxy_mcp_server._SEMGREP_SEVERITY_MAP[semgrep_name]}, pipeline uses {normalized}"

    @patch('appsec_galaxy.scanners.semgrep.subprocess.run')
    @patch('appsec_galaxy.scanners.semgrep.validate_repo_path')
    def test_scanner_pipeline_mapping_unchanged(self, mock_validate, mock_subprocess, mock_repo, output_dir):
        """Anchor the scanner's own mapping so both sides can't drift silently."""
        from appsec_galaxy.scanners.semgrep import run_semgrep
        mock_validate.return_value = mock_repo
        raw = {'results': [
            {'check_id': 'a', 'path': 'x.py', 'start': {'line': 1}, 'extra': {'severity': 'CRITICAL', 'message': 'm'}},
            {'check_id': 'b', 'path': 'x.py', 'start': {'line': 2}, 'extra': {'severity': 'ERROR', 'message': 'm'}},
            {'check_id': 'c', 'path': 'x.py', 'start': {'line': 3}, 'extra': {'severity': 'WARNING', 'message': 'm'}},
            {'check_id': 'd', 'path': 'x.py', 'start': {'line': 4}, 'extra': {'severity': 'INFO', 'message': 'm'}},
        ]}

        def create_output_file(*args, **kwargs):
            (output_dir / 'semgrep.json').write_text(json.dumps(raw))
            result = Mock()
            result.returncode = 1
            result.stdout = ''
            result.stderr = ''
            return result

        mock_subprocess.side_effect = create_output_file
        findings = run_semgrep(str(mock_repo), str(output_dir), scan_level='all')
        by_id = {f['check_id']: f['severity'] for f in findings}
        assert by_id == {'a': 'critical', 'b': 'high', 'c': 'medium', 'd': 'low'}

def test_gitleaks_config_extends_upstream_ruleset():
    """The bundled gitleaks config must inherit the maintained upstream rules.

    Without [extend] useDefault, detection is frozen at the ~20 hand-written
    rules in this file: any credential format a provider introduces or
    rotates later is silently undetectable, and nothing warns.
    """
    checkout_root = Path(__file__).resolve().parent.parent
    config = (checkout_root / "configs" / ".gitleaks.toml").read_text()

    assert "[extend]" in config
    assert re.search(r"^\s*useDefault\s*=\s*true", config, re.M)
    # The custom rules cover shapes the defaults miss; they must survive.
    assert len(re.findall(r"^\[\[rules\]\]", config, re.M)) >= 10
    # Custom rules that duplicate an upstream shape under a different id
    # made every such secret report twice; a custom rule that REUSES an
    # upstream id replaces it (see the sourcegraph override), so the old
    # narrower "private-key" rule silently lost OpenSSH/PGP detection.
    ids = set(re.findall(r'^id = "([^"]+)"', config, re.M))
    assert not ids & {"aws-access-key", "github-token", "slack-webhook", "google-api-key",
                      "stripe-api-key", "sendgrid-api-key", "twilio-api-key",
                      "private-key", "pem-private-key"}
    # The bundled config is applied to *scanned* repos, so a broad path
    # allowlist here would hide real secrets in someone else's repository.
    # Repo-local noise belongs in this repo's .gitleaksignore instead.
    assert "outputs/" not in config

def test_gitleaks_sourcegraph_rule_requires_token_prefix():
    """Regression: upstream's sourcegraph-access-token regex accepts any bare
    40-hex string, so SBOMs and lockfiles full of SHA-1 hashes produced 610
    false "secrets" on one repo's git history. The bundled override keeps
    the rule id (replacing upstream's rule, not adding a second one) and
    only matches the real sgp_ token shapes."""
    import re as _re
    checkout_root = Path(__file__).resolve().parent.parent
    config = tomllib.loads((checkout_root / "configs" / ".gitleaks.toml").read_text())
    rules = [r for r in config["rules"] if r["id"] == "sourcegraph-access-token"]
    assert len(rules) == 1
    pattern = _re.compile(rules[0]["regex"])
    sha1 = "a" * 40
    assert not pattern.search(f'"hash": "{sha1}"')
    assert not pattern.search(f'sourcegraph {sha1} ')
    assert pattern.search(f'token = "sgp_{"b" * 16}_{sha1}"')
    assert pattern.search(f'token = "sgp_local_{sha1}"')
    assert pattern.search(f'token = "sgp_{sha1}"')

@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks binary not installed")
def test_gitleaks_binary_detects_openssh_key_and_reports_aws_key_once(tmp_path):
    """Regression: a custom "private-key" rule shadowed upstream's broader
    one (OpenSSH keys went undetected), and duplicate custom rules made an
    AWS key show up twice."""
    import json as _json
    checkout_root = Path(__file__).resolve().parent.parent
    (tmp_path / "id_ed25519").write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
        "-----END OPENSSH PRIVATE KEY-----\n")
    (tmp_path / "settings.py").write_text('AWS_KEY = "AKIAZ9Q4XK2LM7PT3RVB"\n')
    report = tmp_path / "gl.json"
    subprocess.run(
        ["gitleaks", "detect", "--no-git", "--source", str(tmp_path),
         "--config", str(checkout_root / "configs" / ".gitleaks.toml"),
         "--report-format", "json", "--report-path", str(report),
         "--no-banner", "--exit-code", "0"],
        check=True, capture_output=True, timeout=60,
    )
    hits = _json.loads(report.read_text()) if report.exists() else []
    by_file: dict[str, list[str]] = {}
    for h in hits:
        by_file.setdefault(Path(h["File"]).name, []).append(h["RuleID"])
    assert "private-key" in by_file.get("id_ed25519", [])
    assert len(by_file.get("settings.py", [])) == 1

@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks binary not installed")
def test_run_gitleaks_scans_a_plain_directory(tmp_path):
    """Regression: without --no-git, gitleaks treated a non-git directory as
    a broken repo and wrote an empty report that looked like a clean scan."""
    from appsec_galaxy.scanners.gitleaks import run_gitleaks
    (tmp_path / "settings.py").write_text('AWS_KEY = "AKIAZ9Q4XK2LM7PT3RVB"\n')
    out = tmp_path / "out"
    results = run_gitleaks(str(tmp_path), out)
    assert results, "secret in a plain (non-git) directory must be reported"
    assert all("Secret" not in r and "Match" not in r for r in results)

@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks binary not installed")
def test_gitleaks_binary_ignores_bare_sha1_but_catches_sourcegraph_token(tmp_path):
    """End to end through the real binary: the override must actually replace
    the upstream rule when the config is applied via [extend]."""
    import json as _json
    checkout_root = Path(__file__).resolve().parent.parent
    sha1 = "0123456789abcdef0123456789abcdef01234567"
    (tmp_path / "sbom.json").write_text(
        '{"name": "sourcegraph-client", "hashes": [{"alg": "SHA-1", "content": "%s"}]}\n' % sha1
    )
    (tmp_path / "settings.py").write_text('SG_TOKEN = "sgp_fedcba9876543210_%s"\n' % sha1)
    report = tmp_path / "gl.json"
    subprocess.run(
        ["gitleaks", "detect", "--no-git", "--source", str(tmp_path),
         "--config", str(checkout_root / "configs" / ".gitleaks.toml"),
         "--report-format", "json", "--report-path", str(report),
         "--no-banner", "--exit-code", "0"],
        check=True, capture_output=True, timeout=60,
    )
    hits = _json.loads(report.read_text()) if report.exists() else []
    by_file = {Path(h["File"]).name for h in hits if h["RuleID"] == "sourcegraph-access-token"}
    assert by_file == {"settings.py"}

def test_bundled_scanner_configs_resolve_to_checkout():
    from appsec_galaxy.scanners.checkstyle import CheckstyleScanner

    checkout_root = Path(__file__).resolve().parent.parent
    scanner = CheckstyleScanner()

    assert scanner.configs_dir == checkout_root / "configs"
    assert (scanner.configs_dir / ".gitleaks.toml").is_file()
    assert (scanner.configs_dir / "eslint.config.js").is_file()
    assert (scanner.configs_dir / "checkstyle.xml").is_file()
