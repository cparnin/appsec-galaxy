"""
Scan orchestration and the CLI: menus, mode selection, the shared
finalize_scan pipeline, baselines, diff scoping, history, and retention.
"""

import pytest
import json
import os
from pathlib import Path
from unittest.mock import patch
import sys




class TestCLIInteractiveMenu:
    """Tests for the interactive menu in src/main.py.

    These verify that the menu collapsed correctly after the
    tool_ingestion option was removed: only [1] Scan and [q] Quit
    should be valid choices."""

    @pytest.fixture
    def menu_fn(self):
        if 'appsec_galaxy.main' in sys.modules:
            del sys.modules['appsec_galaxy.main']
        from appsec_galaxy import main as main_module
        return main_module.show_interactive_menu

    def test_accepts_choice_1(self, menu_fn, monkeypatch, capsys):
        monkeypatch.setattr('builtins.input', lambda _prompt='': '1')
        assert menu_fn() == '1'

    def test_accepts_choice_q(self, menu_fn, monkeypatch):
        monkeypatch.setattr('builtins.input', lambda _prompt='': 'q')
        assert menu_fn() == 'q'

    def test_accepts_uppercase_Q(self, menu_fn, monkeypatch):
        """Menu lowercases input, so 'Q' should work."""
        monkeypatch.setattr('builtins.input', lambda _prompt='': 'Q')
        assert menu_fn() == 'q'

    def test_rejects_choice_2_post_tool_ingestion_removal(self, menu_fn, monkeypatch, capsys):
        """After tool_ingestion was removed, choice '2' is no longer valid.
        The menu should re-prompt rather than accept it."""
        responses = iter(['2', 'q'])
        monkeypatch.setattr('builtins.input', lambda _prompt='': next(responses))
        result = menu_fn()
        assert result == 'q'  # eventually accepted q, not 2
        captured = capsys.readouterr()
        assert "Invalid choice" in captured.out

    def test_rejects_garbage_input(self, menu_fn, monkeypatch, capsys):
        responses = iter(['xyz', '99', '', 'q'])
        monkeypatch.setattr('builtins.input', lambda _prompt='': next(responses))
        result = menu_fn()
        assert result == 'q'
        captured = capsys.readouterr()
        # All three garbage inputs should have triggered a re-prompt
        assert captured.out.count("Invalid choice") == 3

class TestCLISeveritySelection:
    """Tests for select_scan_level in src/main.py."""

    @pytest.fixture
    def select_fn(self):
        if 'appsec_galaxy.main' in sys.modules:
            del sys.modules['appsec_galaxy.main']
        from appsec_galaxy import main as main_module
        return main_module.select_scan_level

    def test_choice_1_returns_critical_high(self, select_fn, monkeypatch):
        monkeypatch.setattr('builtins.input', lambda _prompt='': '1')
        assert select_fn() == 'critical-high'

    def test_choice_2_returns_all(self, select_fn, monkeypatch):
        monkeypatch.setattr('builtins.input', lambda _prompt='': '2')
        assert select_fn() == 'all'

class TestClassifyDir:
    """Tests for _classify_dir helper."""

    def test_git_repo(self, tmp_path):
        (tmp_path / '.git').mkdir()
        from appsec_galaxy.main import _classify_dir
        assert _classify_dir(str(tmp_path)) == 'git'

    def test_nodejs_project(self, tmp_path):
        (tmp_path / 'package.json').touch()
        from appsec_galaxy.main import _classify_dir
        assert _classify_dir(str(tmp_path)) == 'nodejs'

    def test_python_project(self, tmp_path):
        (tmp_path / 'requirements.txt').touch()
        from appsec_galaxy.main import _classify_dir
        assert _classify_dir(str(tmp_path)) == 'python'

    def test_plain_directory(self, tmp_path):
        from appsec_galaxy.main import _classify_dir
        assert _classify_dir(str(tmp_path)) == 'dir'

    def test_git_takes_priority(self, tmp_path):
        (tmp_path / '.git').mkdir()
        (tmp_path / 'package.json').touch()
        from appsec_galaxy.main import _classify_dir
        assert _classify_dir(str(tmp_path)) == 'git'

class TestBrowseDirectoriesInteractive:
    """Tests for _browse_directories_interactive with mocked input."""

    def test_quit_immediately(self, monkeypatch):
        from appsec_galaxy.main import _browse_directories_interactive
        monkeypatch.setattr('builtins.input', lambda _: 'q')
        result = _browse_directories_interactive()
        assert result is None

    def test_select_with_s_prefix(self, tmp_path, monkeypatch):
        from appsec_galaxy.main import _browse_directories_interactive

        repo = tmp_path / 'my-repo'
        repo.mkdir()
        (repo / '.git').mkdir()

        inputs = iter(['1', 's1'])
        monkeypatch.setattr('builtins.input', lambda _: next(inputs))
        monkeypatch.setenv('REPO_SEARCH_PATHS', str(tmp_path))
        monkeypatch.chdir(tmp_path)
        result = _browse_directories_interactive()
        assert result == str(repo)

class TestAutoModeScannerSelection:
    """
    Regression for auto-mode (GitHub Actions / MCP) scanner selection.

    The bug: src/main.py used to hardcode scanners_to_run to
    ["semgrep", "gitleaks", "trivy"], ignoring APPSEC_AI_SCAN=true.
    AI scan never engaged via the MCP server, contradicting the docs
    that claimed "MCP and CI/CD always run all tools" and silently
    breaking the AI deep analysis feature for every MCP user.

    The fix: _build_auto_mode_scanner_list() honors APPSEC_AI_SCAN,
    matching the contract used by the interactive select_tools() path.
    """

    def test_default_excludes_ai_scan(self, monkeypatch):
        """Unset APPSEC_AI_SCAN means rule-based only (fail-closed on data exposure)."""
        from appsec_galaxy.main import _build_auto_mode_scanner_list
        monkeypatch.delenv('APPSEC_AI_SCAN', raising=False)
        scanners = _build_auto_mode_scanner_list()
        assert scanners == ["semgrep", "gitleaks", "trivy"]
        assert "ai_scan" not in scanners

    def test_explicit_false_excludes_ai_scan(self, monkeypatch):
        """APPSEC_AI_SCAN=false must NOT include AI scan."""
        from appsec_galaxy.main import _build_auto_mode_scanner_list
        monkeypatch.setenv('APPSEC_AI_SCAN', 'false')
        scanners = _build_auto_mode_scanner_list()
        assert "ai_scan" not in scanners

    def test_explicit_true_includes_ai_scan(self, monkeypatch):
        """APPSEC_AI_SCAN=true must include AI scan in auto mode."""
        from appsec_galaxy.main import _build_auto_mode_scanner_list
        monkeypatch.setenv('APPSEC_AI_SCAN', 'true')
        scanners = _build_auto_mode_scanner_list()
        assert "ai_scan" in scanners

    def test_ai_scan_appended_last_for_dedup(self, monkeypatch):
        """
        AI scan must run AFTER rule-based scanners so that
        ai_scanner._deduplicate_against_existing() has semgrep.json /
        trivy-sca.json on disk to dedup against. Order matters.
        """
        from appsec_galaxy.main import _build_auto_mode_scanner_list
        monkeypatch.setenv('APPSEC_AI_SCAN', 'true')
        scanners = _build_auto_mode_scanner_list()
        assert scanners[-1] == "ai_scan"
        for rule_based in ("semgrep", "gitleaks", "trivy"):
            assert scanners.index(rule_based) < scanners.index("ai_scan")

    def test_case_insensitive_true(self, monkeypatch):
        """APPSEC_AI_SCAN parsing must be case-insensitive (matches select_tools logic)."""
        from appsec_galaxy.main import _build_auto_mode_scanner_list
        monkeypatch.setenv('APPSEC_AI_SCAN', 'TRUE')
        scanners = _build_auto_mode_scanner_list()
        assert "ai_scan" in scanners

    def test_garbage_value_treated_as_false(self, monkeypatch):
        """Any value other than 'true' (case-insensitive) must NOT enable AI scan."""
        from appsec_galaxy.main import _build_auto_mode_scanner_list
        monkeypatch.setenv('APPSEC_AI_SCAN', 'yes')  # Truthy in some langs, not for us
        scanners = _build_auto_mode_scanner_list()
        assert "ai_scan" not in scanners

class TestAutoModeZeroFindings:
    """Regression: a clean scan (zero findings) in CI must not crash.

    run_auto_mode returns enhanced_findings, but that name was only bound
    inside the has-findings branch, so a scan that found nothing raised
    UnboundLocalError and failed the job (the self-scan broke the moment
    the repo scanned clean)."""

    def test_zero_findings_returns_empty_without_crash(self, tmp_path, monkeypatch):
        if 'appsec_galaxy.main' in sys.modules:
            del sys.modules['appsec_galaxy.main']
        from appsec_galaxy import main as m
        (tmp_path / '.git').mkdir()
        out = tmp_path / 'out'
        (out / 'raw').mkdir(parents=True)
        monkeypatch.setattr(m, 'is_github_actions', lambda: True)
        monkeypatch.setattr(m, 'validate_repo_path', lambda p: tmp_path)
        monkeypatch.setattr(m, 'get_output_path', lambda *a, **k: str(out))
        monkeypatch.setattr(m, 'cleanup_old_scans', lambda *a, **k: None)
        monkeypatch.setattr(m, 'setup_output_directories', lambda *a, **k: {'base': out})
        monkeypatch.setattr(m, 'run_security_scans', lambda *a, **k: [])  # clean scan
        monkeypatch.setattr(m, 'SBOM_AVAILABLE', False)
        monkeypatch.setenv('GITHUB_WORKSPACE', str(tmp_path))
        result = m.run_auto_mode()
        assert result == []

class TestAppSecGalaxySettings:
    """Validated env config (pydantic-settings) in src/config.py."""

    def _fresh(self, monkeypatch, **env):
        """Build AppSecGalaxySettings with a controlled environment."""
        from appsec_galaxy.config import AppSecGalaxySettings
        for var in ('APPSEC_CODE_QUALITY', 'APPSEC_CODE_QUALITY_MIN_SEVERITY',
                    'APPSEC_AI_SCAN', 'APPSEC_AI_SCAN_DEPTH',
                    'APPSEC_AI_SCAN_MAX_FILES', 'APPSEC_AI_SCAN_TIER',
                    'APPSEC_AI_SCAN_MAX_COST', 'APPSEC_SEMGREP_CONFIG',
                    'APPSEC_DEPENDENCY_ANALYSIS', 'APPSEC_DEP_HEALTH_CHECK',
                    'APPSEC_TRIVY_SCANNERS'):
            monkeypatch.delenv(var, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        return AppSecGalaxySettings()

    def test_empty_env_values_count_as_unset(self, monkeypatch):
        """Regression: the GitHub Action exports every input, so an input left
        at its default arrives as APPSEC_AI_SCAN_MAX_COST='' and float parsing
        failed at startup (every client run on v2.6.3)."""
        s = self._fresh(monkeypatch, APPSEC_AI_SCAN_MAX_COST='', APPSEC_AI_SCAN_MAX_FILES='',
                        APPSEC_AI_SCAN_TIER='', APPSEC_AI_SCAN_DEPTH='')
        assert s.ai_scan_max_cost == 0.0
        assert s.ai_scan_max_files == 50
        assert s.ai_scan_tier == 3
        assert s.ai_scan_depth == 'standard'

    def test_defaults(self, monkeypatch):
        s = self._fresh(monkeypatch)
        assert s.code_quality is True
        assert s.code_quality_min_severity == 'high'
        assert s.ai_scan is False
        assert s.ai_scan_depth == 'standard'
        assert s.ai_scan_max_files == 50
        assert s.ai_scan_tier == 3
        assert s.dependency_analysis is True
        assert s.dep_health_check is True
        assert s.trivy_scanners == 'vuln,misconfig'

    def test_valid_overrides(self, monkeypatch):
        s = self._fresh(monkeypatch,
                        APPSEC_AI_SCAN='true',
                        APPSEC_AI_SCAN_DEPTH='DEEP',
                        APPSEC_AI_SCAN_MAX_FILES='10',
                        APPSEC_AI_SCAN_TIER='2',
                        APPSEC_CODE_QUALITY_MIN_SEVERITY='Medium')
        assert s.ai_scan is True
        assert s.ai_scan_depth == 'deep'  # lowercased
        assert s.ai_scan_max_files == 10
        assert s.ai_scan_tier == 2
        assert s.code_quality_min_severity == 'medium'  # lowercased

    def test_invalid_int_fails_loudly(self, monkeypatch):
        with pytest.raises(Exception) as exc_info:
            self._fresh(monkeypatch, APPSEC_AI_SCAN_MAX_FILES='abc')
        assert 'APPSEC_AI_SCAN_MAX_FILES' in str(exc_info.value) or 'ai_scan_max_files' in str(exc_info.value).lower()

    def test_invalid_depth_fails_loudly(self, monkeypatch):
        with pytest.raises(Exception) as exc_info:
            self._fresh(monkeypatch, APPSEC_AI_SCAN_DEPTH='fast')
        assert 'APPSEC_AI_SCAN_DEPTH' in str(exc_info.value)

    def test_invalid_severity_fails_loudly(self, monkeypatch):
        with pytest.raises(Exception) as exc_info:
            self._fresh(monkeypatch, APPSEC_CODE_QUALITY_MIN_SEVERITY='extreme')
        assert 'APPSEC_CODE_QUALITY_MIN_SEVERITY' in str(exc_info.value)

    def test_tier_out_of_range_fails(self, monkeypatch):
        with pytest.raises(Exception):
            self._fresh(monkeypatch, APPSEC_AI_SCAN_TIER='9')

    def test_trivy_scanners_normalized(self, monkeypatch):
        s = self._fresh(monkeypatch, APPSEC_TRIVY_SCANNERS=' VULN , misconfig ,vuln')
        assert s.trivy_scanners == 'vuln,misconfig'  # lowercased, deduped

    def test_trivy_scanners_vuln_only(self, monkeypatch):
        s = self._fresh(monkeypatch, APPSEC_TRIVY_SCANNERS='vuln')
        assert s.trivy_scanners == 'vuln'

    def test_invalid_trivy_scanners_fails_loudly(self, monkeypatch):
        with pytest.raises(Exception) as exc_info:
            self._fresh(monkeypatch, APPSEC_TRIVY_SCANNERS='vuln,license')
        assert 'APPSEC_TRIVY_SCANNERS' in str(exc_info.value)

    def test_module_constants_exposed(self):
        """Backwards-compat constant names must survive the migration."""
        from appsec_galaxy import config
        for name in ('ENABLE_CODE_QUALITY', 'CODE_QUALITY_MIN_SEVERITY',
                     'ENABLE_AI_SCAN', 'AI_SCAN_DEPTH', 'AI_SCAN_MAX_FILES',
                     'AI_SCAN_TIER', 'ENABLE_DEPENDENCY_ANALYSIS',
                     'DEPENDENCY_HEALTH_CHECK'):
            assert hasattr(config, name), f"config.{name} missing"

class TestProjectPathsResolution:
    """Resource paths resolve to the repo root in a source checkout and to
    the working directory when pip-installed. Regression: installed runs
    (self-scan, the Action) wrote outputs next to site-packages, where the
    SARIF upload, artifact upload, and fail-on-critical gate never looked.
    """

    def test_source_checkout_uses_checkout_root(self, tmp_path):
        from appsec_galaxy.project_paths import _resolve_resource_root
        (tmp_path / 'pyproject.toml').write_text('[project]\nname = "x"\n')
        assert _resolve_resource_root(tmp_path) == tmp_path

    def test_installed_package_falls_back_to_cwd(self, tmp_path):
        from appsec_galaxy.project_paths import _resolve_resource_root
        # tmp_path has no pyproject.toml, like site-packages' parent
        assert _resolve_resource_root(tmp_path) == Path.cwd()

    def test_this_checkout_resolves_to_repo_root(self):
        """Dev behavior is unchanged: outputs at the repo root."""
        from appsec_galaxy import project_paths
        repo_root = Path(__file__).resolve().parent.parent
        assert project_paths.OUTPUTS_DIR == repo_root / 'outputs'
        assert project_paths.CONFIGS_DIR == repo_root / 'configs'

class TestPostScanPipeline:
    """Integration: apply_post_scan_pipeline in src/main.py wires suppression,
    diff scoping, enrichment, SARIF, and history together."""

    def test_full_pipeline_end_to_end(self, tmp_path, monkeypatch):
        from appsec_galaxy.main import apply_post_scan_pipeline
        monkeypatch.setenv('APPSEC_VULN_INTEL', 'false')   # no network in CI
        monkeypatch.delenv('APPSEC_DIFF_ONLY', raising=False)

        repo = tmp_path / 'repo'
        repo.mkdir()
        (repo / '.appsec-galaxy-ignore').write_text("semgrep:ignored-rule:*\n")
        output_dir = tmp_path / 'outputs'
        output_dir.mkdir()

        findings = [
            {'tool': 'semgrep', 'check_id': 'ignored-rule', 'path': 'a.py',
             'start': {'line': 1}, 'extra': {'message': 'suppressed'}, 'severity': 'high'},
            {'tool': 'semgrep', 'check_id': 'kept-rule', 'path': 'b.py',
             'start': {'line': 2}, 'extra': {'message': 'kept'}, 'severity': 'critical'},
        ]
        result = apply_post_scan_pipeline(findings, str(repo), output_dir)

        # Suppression applied
        assert len(result) == 1
        assert result[0]['check_id'] == 'kept-rule'
        # SARIF written with only the kept finding
        sarif = json.loads((output_dir / 'report.sarif').read_text())
        assert len(sarif['runs'][0]['results']) == 1
        # History recorded
        history = json.loads((output_dir / 'history.json').read_text())
        assert history[-1]['total'] == 1

    def test_pipeline_second_run_reports_trend(self, tmp_path, monkeypatch, capsys):
        from appsec_galaxy.main import apply_post_scan_pipeline
        monkeypatch.setenv('APPSEC_VULN_INTEL', 'false')
        monkeypatch.delenv('APPSEC_DIFF_ONLY', raising=False)
        repo = tmp_path / 'repo'
        repo.mkdir()
        output_dir = tmp_path / 'outputs'

        f1 = {'tool': 'semgrep', 'check_id': 'r1', 'path': 'a.py',
              'start': {'line': 1}, 'extra': {'message': 'm'}, 'severity': 'high'}
        f2 = {'tool': 'semgrep', 'check_id': 'r2', 'path': 'b.py',
              'start': {'line': 1}, 'extra': {'message': 'm'}, 'severity': 'high'}
        apply_post_scan_pipeline([f1], str(repo), output_dir)
        apply_post_scan_pipeline([f2], str(repo), output_dir)
        out = capsys.readouterr().out
        assert '1 new, 1 fixed' in out

class TestFinalizeScan:
    """finalize_scan is the ONE post-scan report pipeline for CLI auto, CLI
    interactive, and web mode. It used to be pasted three times and had
    drifted (web omitted detected languages, remediated unenhanced findings,
    and a clean CLI scan wrote no report)."""

    def _run(self, tmp_path, monkeypatch, findings, calls):
        from appsec_galaxy import main as m
        import appsec_galaxy.enhanced_analyzer as ea

        async def fake_pipeline(f, repo):
            calls.append('cross_file')
            return [dict(x, enhanced=True) for x in f], {'pr_summary': 'PR SUMMARY'}

        monkeypatch.setattr(ea, 'run_cross_file_pipeline', fake_pipeline)
        monkeypatch.setattr(m, 'CROSS_FILE_AVAILABLE', True)
        monkeypatch.setattr(m, 'ENABLE_DEPENDENCY_ANALYSIS', False)
        monkeypatch.setattr(m, 'SBOM_AVAILABLE', False)
        repo = tmp_path / 'repo'
        repo.mkdir(exist_ok=True)
        out = tmp_path / 'out'
        out.mkdir(exist_ok=True)
        return m.finalize_scan(findings, str(repo), out, run_sbom=False), out

    def test_runs_cross_file_once_and_returns_enhanced_findings(self, tmp_path, monkeypatch):
        calls: list[str] = []
        findings = [{'tool': 'semgrep', 'check_id': 'x', 'path': 'a.py', 'severity': 'high',
                     'start': {'line': 1}, 'extra': {'message': 'm'}, 'category': 'security'}]
        enhanced, out = self._run(tmp_path, monkeypatch, findings, calls)
        assert calls == ['cross_file'], "the AI cross-file layer must run exactly once per scan"
        assert enhanced[0]['enhanced'] is True
        assert (out / 'report.html').exists()
        assert (out / 'pr-findings.txt').read_text() == 'PR SUMMARY'

    def test_clean_scan_still_writes_a_report(self, tmp_path, monkeypatch):
        calls: list[str] = []
        enhanced, out = self._run(tmp_path, monkeypatch, [], calls)
        assert enhanced == [] and calls == []
        assert (out / 'report.html').exists()
        assert 'Low Risk' in (out / 'report.html').read_text()

    def test_no_inline_copies_of_the_pipeline_remain(self):
        """Every mode must call finalize_scan rather than re-implement it."""
        root = Path(__file__).resolve().parent.parent / 'src' / 'appsec_galaxy'
        for name in ('main.py', 'web_app.py'):
            src = (root / name).read_text()
            assert 'enhance_findings_with_cross_file(' not in src, name
            assert 'generate_cross_file_enhanced_report(' not in src, name
        assert (root / 'web_app.py').read_text().count('finalize_scan(') == 1
        assert (root / 'main.py').read_text().count('= finalize_scan(') == 2  # auto + interactive

class TestScanLevelResolution:
    def test_invalid_level_falls_back_instead_of_reaching_semgrep(self, monkeypatch):
        """Regression: run_auto_mode re-read the raw env after validation, so
        APPSEC_SCAN_LEVEL=high made semgrep's filter match nothing and CI
        passed green with zero SAST findings."""
        from appsec_galaxy.main import resolve_scan_level
        monkeypatch.setenv('APPSEC_SCAN_LEVEL', 'high')
        assert resolve_scan_level() == 'critical-high'
        monkeypatch.setenv('APPSEC_SCAN_LEVEL', ' ALL ')
        assert resolve_scan_level() == 'all'

    def test_auto_fix_mode_narrows_to_available_findings(self, monkeypatch, capsys):
        """Regression: mode 1 with only dependency findings printed
        "Auto-remediation complete" without doing anything."""
        import sys
        if 'appsec_galaxy.main' in sys.modules:
            del sys.modules['appsec_galaxy.main']
        from appsec_galaxy import main as m
        monkeypatch.setenv('GITHUB_ACTIONS', 'true')
        monkeypatch.delenv('GITHUB_EVENT_NAME', raising=False)
        monkeypatch.setenv('APPSEC_AUTO_FIX', 'true')
        monkeypatch.setenv('APPSEC_AUTO_FIX_MODE', '1')
        deps_only = [{'tool': 'trivy', 'vulnerability_id': 'CVE-1', 'severity': 'high',
                      'path': 'requirements.txt', 'fixed_version': '2.0', 'pkg_name': 'x'}]
        with patch('appsec_galaxy.auto_remediation.remediation.create_remediation_pr') as mock_pr:
            result = m.handle_auto_remediation('/tmp/repo', deps_only)
        assert not mock_pr.called
        assert 'Adjusting mode 1 to 4' in capsys.readouterr().out
        assert result['message'] == 'Auto-fix skipped'

class TestAppSecGalaxyIgnore:
    """Baseline suppression via .appsec-galaxy-ignore (src/scan_filters.py)."""

    def _write_ignore(self, tmp_path, content):
        (tmp_path / '.appsec-galaxy-ignore').write_text(content)
        return str(tmp_path)

    def test_no_file_is_noop(self, tmp_path):
        from appsec_galaxy.scan_filters import filter_suppressed
        findings = [{'tool': 'semgrep', 'check_id': 'x', 'path': 'a.py'}]
        kept, suppressed = filter_suppressed(findings, str(tmp_path))
        assert kept == findings and suppressed == 0

    def test_exact_match_suppressed(self, tmp_path):
        from appsec_galaxy.scan_filters import filter_suppressed
        repo = self._write_ignore(tmp_path, "semgrep:js.sqli:app.js\n")
        findings = [
            {'tool': 'semgrep', 'check_id': 'js.sqli', 'path': 'app.js'},
            {'tool': 'semgrep', 'check_id': 'js.xss', 'path': 'app.js'},
        ]
        kept, suppressed = filter_suppressed(findings, repo)
        assert suppressed == 1
        assert kept[0]['check_id'] == 'js.xss'

    def test_glob_patterns(self, tmp_path):
        from appsec_galaxy.scan_filters import filter_suppressed
        repo = self._write_ignore(tmp_path, "*:*:tests/fixtures/*\n")
        findings = [
            {'tool': 'gitleaks', 'RuleID': 'key', 'File': 'tests/fixtures/fake.pem'},
            {'tool': 'gitleaks', 'RuleID': 'key', 'File': 'src/real.pem'},
        ]
        kept, suppressed = filter_suppressed(findings, repo)
        assert suppressed == 1
        assert kept[0]['File'] == 'src/real.pem'

    def test_comments_and_malformed_lines_skipped(self, tmp_path):
        from appsec_galaxy.scan_filters import load_ignore_patterns
        repo = self._write_ignore(tmp_path, "# comment\n\nnot-valid-line\nsemgrep:rule:path\n")
        patterns = load_ignore_patterns(repo)
        assert patterns == [('semgrep', 'rule', 'path')]

    def test_absolute_paths_normalized(self, tmp_path):
        from appsec_galaxy.scan_filters import filter_suppressed
        repo = self._write_ignore(tmp_path, "trivy:CVE-2024-1:package-lock.json\n")
        findings = [{'tool': 'trivy', 'vulnerability_id': 'CVE-2024-1',
                     'path': f'{tmp_path}/package-lock.json'}]
        kept, suppressed = filter_suppressed(findings, repo)
        assert suppressed == 1

class TestDiffOnly:
    """PR-diff scoping (APPSEC_DIFF_ONLY) in src/scan_filters.py."""

    def test_disabled_by_default(self, monkeypatch, tmp_path):
        from appsec_galaxy.scan_filters import filter_diff_only
        monkeypatch.delenv('APPSEC_DIFF_ONLY', raising=False)
        findings = [{'tool': 'semgrep', 'path': 'a.py'}]
        kept, filtered = filter_diff_only(findings, str(tmp_path))
        assert kept == findings and filtered == 0

    def test_filters_to_changed_files(self, monkeypatch, tmp_path):
        from appsec_galaxy import scan_filters
        monkeypatch.setenv('APPSEC_DIFF_ONLY', 'true')
        monkeypatch.setattr(scan_filters, 'get_changed_files', lambda repo, base_ref=None: {'app.js'})
        findings = [
            {'tool': 'semgrep', 'check_id': 'x', 'path': 'app.js'},
            {'tool': 'semgrep', 'check_id': 'x', 'path': 'other.js'},
            {'tool': 'trivy', 'vulnerability_id': 'CVE-1', 'path': 'package-lock.json'},
        ]
        kept, filtered = scan_filters.filter_diff_only(findings, str(tmp_path))
        assert len(kept) == 1 and kept[0]['path'] == 'app.js'
        assert filtered == 2

    def test_fails_open_when_git_unusable(self, monkeypatch, tmp_path):
        from appsec_galaxy import scan_filters
        monkeypatch.setenv('APPSEC_DIFF_ONLY', 'true')
        monkeypatch.setattr(scan_filters, 'get_changed_files', lambda repo, base_ref=None: None)
        findings = [{'tool': 'semgrep', 'path': 'a.py'}]
        kept, filtered = scan_filters.filter_diff_only(findings, str(tmp_path))
        assert kept == findings and filtered == 0

    def test_get_changed_files_parses_git_output(self, monkeypatch, tmp_path):
        from appsec_galaxy import scan_filters
        class FakeResult:
            def __init__(self, rc, out):
                self.returncode, self.stdout = rc, out

        calls = []
        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if '...' in cmd[-1]:
                return FakeResult(0, "app.js\nsrc/db.py\n")
            return FakeResult(0, "uncommitted.py\n")
        monkeypatch.setattr(scan_filters.subprocess, 'run', fake_run)
        changed = scan_filters.get_changed_files(str(tmp_path), 'origin/main')
        assert changed == {'app.js', 'src/db.py', 'uncommitted.py'}
        assert all(c[0] == 'git' for c in calls)

    def test_get_changed_files_falls_back_through_refs(self, monkeypatch, tmp_path):
        from appsec_galaxy import scan_filters
        class FakeResult:
            def __init__(self, rc, out=''):
                self.returncode, self.stdout = rc, out

        def fake_run(cmd, **kwargs):
            if 'origin/master...HEAD' in cmd[-1]:
                return FakeResult(0, "found.py\n")
            return FakeResult(128)  # origin/main missing
        monkeypatch.setattr(scan_filters.subprocess, 'run', fake_run)
        monkeypatch.delenv('APPSEC_DIFF_BASE', raising=False)
        changed = scan_filters.get_changed_files(str(tmp_path))
        assert 'found.py' in changed

class TestScanHistory:
    """Trend history (src/scan_history.py)."""

    def _finding(self, rule, path='a.py', tool='semgrep', severity='high'):
        return {'tool': tool, 'check_id': rule, 'path': path, 'severity': severity}

    def test_first_scan(self, tmp_path):
        from appsec_galaxy.scan_history import record_and_diff
        delta = record_and_diff([self._finding('r1'), self._finding('r2')], tmp_path)
        assert delta['first_scan'] is True
        assert delta['total'] == 2
        assert (tmp_path / 'history.json').exists()

    def test_new_and_fixed_delta(self, tmp_path):
        from appsec_galaxy.scan_history import record_and_diff
        record_and_diff([self._finding('r1'), self._finding('r2')], tmp_path)
        delta = record_and_diff([self._finding('r2'), self._finding('r3')], tmp_path)
        assert delta['first_scan'] is False
        assert delta['new'] == 1      # r3
        assert delta['fixed'] == 1    # r1
        assert delta['previous_total'] == 2

    def test_fingerprint_stable_across_line_drift(self):
        from appsec_galaxy.scan_history import fingerprint
        a = {'tool': 'semgrep', 'check_id': 'r', 'path': 'a.py', 'start': {'line': 5}}
        b = {'tool': 'semgrep', 'check_id': 'r', 'path': 'a.py', 'start': {'line': 99}}
        assert fingerprint(a) == fingerprint(b)

    def test_fingerprint_contains_no_secret_material(self, tmp_path):
        from appsec_galaxy.scan_history import record_and_diff
        secret_finding = {'tool': 'gitleaks', 'RuleID': 'aws-key', 'File': 'cfg.py',
                          'Secret': 'AKIA_SUPER_SECRET_VALUE'}
        record_and_diff([secret_finding], tmp_path)
        raw = (tmp_path / 'history.json').read_text()
        assert 'AKIA_SUPER_SECRET_VALUE' not in raw

    def test_history_capped_at_max_entries(self, tmp_path):
        from appsec_galaxy import scan_history
        for i in range(scan_history._MAX_ENTRIES + 5):
            scan_history.record_and_diff([self._finding(f'r{i}')], tmp_path)
        history = json.loads((tmp_path / 'history.json').read_text())
        assert len(history) == scan_history._MAX_ENTRIES

    def test_corrupt_history_fails_open(self, tmp_path):
        from appsec_galaxy.scan_history import record_and_diff
        (tmp_path / 'history.json').write_text('{not json')
        delta = record_and_diff([self._finding('r1')], tmp_path)
        assert delta['total'] == 1  # scan continues

class TestCleanupPreservesHistory:
    """Regression: cleanup_old_scans wiped history.json, resetting the scan
    trend (new vs fixed) on every run."""

    def test_history_survives_cleanup(self, tmp_path):
        from appsec_galaxy.path_utils import cleanup_old_scans
        (tmp_path / 'raw').mkdir()
        (tmp_path / 'raw' / 'semgrep.json').write_text('{}')
        (tmp_path / 'report.html').write_text('<html></html>')
        (tmp_path / 'history.json').write_text('[{"total": 5}]')

        cleanup_old_scans(tmp_path)

        assert (tmp_path / 'history.json').exists(), "trend history must survive cleanup"
        assert not (tmp_path / 'raw').exists()
        assert not (tmp_path / 'report.html').exists()

class TestOutputRetention:
    """APPSEC_OUTPUT_RETENTION_DAYS purges stale per-repo output dirs."""

    def _make_repo_dir(self, base, name, age_days):
        import time
        d = base / name
        d.mkdir(parents=True)
        (d / 'history.json').write_text('[]')
        old = time.time() - age_days * 86400
        os.utime(d / 'history.json', (old, old))
        os.utime(d, (old, old))
        return d

    def test_stale_dirs_purged_fresh_kept(self, tmp_path, monkeypatch):
        from appsec_galaxy.path_utils import purge_stale_outputs
        monkeypatch.delenv('APPSEC_OUTPUT_RETENTION_DAYS', raising=False)
        stale = self._make_repo_dir(tmp_path, 'old-client', age_days=45)
        fresh = self._make_repo_dir(tmp_path, 'active-repo', age_days=2)
        purged = purge_stale_outputs(tmp_path)
        assert purged == 1
        assert not stale.exists()
        assert fresh.exists()

    def test_zero_disables_retention(self, tmp_path, monkeypatch):
        from appsec_galaxy.path_utils import purge_stale_outputs
        monkeypatch.setenv('APPSEC_OUTPUT_RETENTION_DAYS', '0')
        stale = self._make_repo_dir(tmp_path, 'old-client', age_days=400)
        assert purge_stale_outputs(tmp_path) == 0
        assert stale.exists()

    def test_custom_window(self, tmp_path, monkeypatch):
        from appsec_galaxy.path_utils import purge_stale_outputs
        monkeypatch.setenv('APPSEC_OUTPUT_RETENTION_DAYS', '7')
        stale = self._make_repo_dir(tmp_path, 'old', age_days=10)
        fresh = self._make_repo_dir(tmp_path, 'new', age_days=3)
        assert purge_stale_outputs(tmp_path) == 1
        assert not stale.exists() and fresh.exists()

    def test_invalid_env_falls_back_to_default(self, tmp_path, monkeypatch):
        from appsec_galaxy.path_utils import purge_stale_outputs
        monkeypatch.setenv('APPSEC_OUTPUT_RETENTION_DAYS', 'abc')
        self._make_repo_dir(tmp_path, 'old-client', age_days=45)
        assert purge_stale_outputs(tmp_path) == 1  # default 30d applies

    def test_files_in_base_dir_untouched(self, tmp_path, monkeypatch):
        import time
        from appsec_galaxy.path_utils import purge_stale_outputs
        monkeypatch.delenv('APPSEC_OUTPUT_RETENTION_DAYS', raising=False)
        f = tmp_path / 'stray.json'
        f.write_text('{}')
        old = time.time() - 90 * 86400
        os.utime(f, (old, old))
        purge_stale_outputs(tmp_path)
        assert f.exists()

    def test_cleanup_triggers_retention_on_siblings(self, tmp_path, monkeypatch):
        from appsec_galaxy.path_utils import cleanup_old_scans
        monkeypatch.delenv('APPSEC_OUTPUT_RETENTION_DAYS', raising=False)
        stale_sibling = self._make_repo_dir(tmp_path, 'old-client', age_days=45)
        current = tmp_path / 'current-repo'
        current.mkdir()
        cleanup_old_scans(current)
        assert not stale_sibling.exists()

def test_distribution_namespace_imports():
    import appsec_galaxy

    assert appsec_galaxy.__product_name__ == "AppSec Galaxy"
    assert appsec_galaxy.__version__ == "2.6.3"

def test_cli_help_exits_without_starting_scan(monkeypatch, capsys):
    from appsec_galaxy import main

    monkeypatch.setattr(main, "run_security_scans", lambda *args, **kwargs: pytest.fail("scan started"))
    with pytest.raises(SystemExit) as exc:
        main.main(["--help"])
    assert exc.value.code == 0
    assert "AppSec Galaxy" in capsys.readouterr().out

def test_default_output_dir_resolves_to_checkout_outputs():
    from appsec_galaxy.config import BASE_OUTPUT_DIR

    checkout_root = Path(__file__).resolve().parent.parent

    assert Path(BASE_OUTPUT_DIR) == checkout_root / "outputs"

@pytest.mark.parametrize("script_name", ["start_cli.sh", "start_web.sh"])
def test_launcher_editable_install_failure_is_not_suppressed(script_name):
    checkout_root = Path(__file__).resolve().parent.parent
    script = (checkout_root / script_name).read_text()
    editable_install = next(
        line.strip()
        for line in script.splitlines()
        if "pip install" in line and " -e " in line
    )

    assert editable_install.startswith(".venv/bin/python -m pip install")
    assert "|" not in editable_install

@pytest.mark.parametrize(
    ("script_name", "module_entrypoint"),
    [
        ("start_cli.sh", "python -m appsec_galaxy.main"),
        ("start_web.sh", "python -m appsec_galaxy.web_app"),
    ],
)
def test_launcher_verifies_package_import_before_launch(script_name, module_entrypoint):
    checkout_root = Path(__file__).resolve().parent.parent
    script = (checkout_root / script_name).read_text()
    import_check = '.venv/bin/python -c "import appsec_galaxy"'

    assert import_check in script
    assert script.index(import_check) < script.index(module_entrypoint)

def test_run_tests_uses_venv_python_module():
    checkout_root = Path(__file__).resolve().parent.parent
    script = (checkout_root / "run_tests.sh").read_text()

    # Must run the whole suite, not one file: naming test_appsec_galaxy.py
    # silently skipped test_ai_provider.py and test_ai_consumers.py, so the
    # local runner disagreed with the CI gate.
    assert ".venv/bin/python -m pytest tests/ -v" in script
    assert "tests/test_appsec_galaxy.py -v" not in script
