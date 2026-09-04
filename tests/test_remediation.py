"""
Auto-remediation safety: PR body sanitization, sandboxing, path
confinement, and the fork-PR gate for the one component allowed to write
and push.
"""

import pytest
import json
from unittest.mock import Mock, patch
import sys




class TestPRBodyMarkdownSanitization:
    """PR bodies interpolate finding text, file paths, package names, and
    AI summaries from the scanned repo. sanitize_markdown_field must defuse
    Markdown/HTML injection (src/auto_remediation/remediation.py)."""

    def _s(self):
        from appsec_galaxy.auto_remediation.remediation import sanitize_markdown_field
        return sanitize_markdown_field

    def test_link_and_image_syntax_neutralized(self):
        s = self._s()
        out = s('click ![img](http://evil.com/x.png)[a](http://evil.com)')
        assert '](' not in out
        assert '[' not in out and ']' not in out
        assert 'http://' not in out  # scheme defanged

    def test_autolinked_url_defanged(self):
        s = self._s()
        out = s('see http://evil.example/steal?c=1')
        assert 'http://' not in out
        assert 'evil.example' in out  # still readable, just not a live link

    def test_mention_defanged(self):
        s = self._s()
        assert '@ evilorg' in s('ping @evilorg now') or '@evilorg' not in s('ping @evilorg now')

    def test_html_and_code_fence_stripped(self):
        s = self._s()
        out = s('<img src=x onerror=alert(1)> ```js\\nbad```')
        assert '<' not in out and '>' not in out
        assert '`' not in out

    def test_newlines_and_length_capped(self):
        s = self._s()
        out = s('a\nb\rc\td', max_len=200)
        assert '\n' not in out and '\r' not in out
        long = s('x' * 500, max_len=50)
        assert len(long) <= 53 and long.endswith('...')

    def test_benign_path_readable(self):
        s = self._s()
        assert s('src/app/db.py') == 'src/app/db.py'

    def test_none_and_nonstring(self):
        s = self._s()
        assert s(None) == ''
        assert s(42) == '42'

    def test_pr_body_end_to_end_neutralizes_hostile_finding(self):
        """A hostile filename/message must not survive into the PR body as a
        live link."""
        from appsec_galaxy.auto_remediation.remediation import AutoRemediator
        r = AutoRemediator.__new__(AutoRemediator)
        r.model = 'test-model'
        findings = [{
            'tool': 'semgrep',
            'severity': 'high',
            'path': 'evil](http://evil.com).py',
            'start': {'line': 1},
            'extra': {'message': 'pwned [click](http://evil.com/steal) @maintainer'},
        }]
        body = r._generate_improved_pr_body(findings, [], 'fix-branch')
        assert '](http://evil.com' not in body
        assert '[click](' not in body
        assert 'http://evil.com' not in body

class TestRemediationSandboxing:
    """Auto-remediation must never execute untrusted repo code when
    regenerating lockfiles (src/auto_remediation/remediation.py).

    The scanned repo is hostile input: npm/yarn preinstall/postinstall
    lifecycle scripts and Go toolchain switching are code-execution
    vectors on the scan host / CI runner."""

    def _remediator(self):
        """Build an AutoRemediator without triggering __init__ (which
        constructs an AI client and needs a key)."""
        from appsec_galaxy.auto_remediation.remediation import AutoRemediator
        r = AutoRemediator.__new__(AutoRemediator)
        r._logged_unsupported_types = set()
        return r

    def _write_pkg(self, tmp_path, lockfile):
        (tmp_path / 'package.json').write_text(json.dumps({
            'name': 'victim', 'dependencies': {'lodash': '^4.17.19'}
        }))
        (tmp_path / lockfile).write_text('{}')
        return str(tmp_path / 'package.json')

    def test_commit_stages_only_touched_files(self, tmp_path, monkeypatch):
        """Regression: `git add .` swept an untracked .env (or a leftover
        manifest backup) into the auto-fix pull request."""
        import subprocess as sp
        calls = []
        monkeypatch.setattr(sp, 'run', lambda cmd, **kw: calls.append(cmd) or Mock(returncode=0, stdout=''))
        r = self._remediator()
        (tmp_path / 'package.json').write_text('{}')
        (tmp_path / 'package-lock.json').write_text('{}')
        r._stage_touched_files(str(tmp_path), [{'file_path': 'package.json'}], ('package-lock.json',))
        assert calls == [['git', 'add', '--', 'package-lock.json', 'package.json']]
        with pytest.raises(ValueError):
            r._stage_touched_files(str(tmp_path), [])

    def test_npm_lockfile_regen_ignores_scripts(self, tmp_path):
        pkg = self._write_pkg(tmp_path, 'package-lock.json')
        with patch('appsec_galaxy.auto_remediation.remediation.subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stderr='', stdout='')
            self._remediator()._update_nodejs_package_json(pkg, 'lodash', '4.17.21', str(tmp_path))
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == 'npm'
        assert '--ignore-scripts' in cmd

    def test_yarn_lockfile_regen_ignores_scripts(self, tmp_path):
        pkg = self._write_pkg(tmp_path, 'yarn.lock')
        with patch('appsec_galaxy.auto_remediation.remediation.subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stderr='', stdout='')
            self._remediator()._update_nodejs_package_json(pkg, 'lodash', '4.17.21', str(tmp_path))
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == 'yarn'
        assert '--ignore-scripts' in cmd

    def test_go_get_pins_toolchain_to_local(self, tmp_path):
        (tmp_path / 'go.mod').write_text('module victim\n\ngo 1.21\n')
        with patch('appsec_galaxy.auto_remediation.remediation.subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stderr='', stdout='')
            self._remediator()._update_go_mod('go.mod', 'github.com/x/y', '1.2.3', str(tmp_path))
        env = mock_run.call_args.kwargs.get('env') or {}
        assert env.get('GOTOOLCHAIN') == 'local'

class TestRemediationPathConfinement:
    """Auto-remediation must confine every file write to the scanned repo.

    A finding's `path` is untrusted scanner output over a potentially
    hostile repo. can_remediate_dependency() gates only on a substring
    match, so a crafted path like `../../../etc/x/requirements.txt` passes
    it; _fix_dependency and apply_fix must reject the escape before any
    file operation. (CodeQL py/path-injection surfaced this flow.)
    """

    def _remediator(self):
        from appsec_galaxy.auto_remediation.remediation import AutoRemediator
        r = AutoRemediator.__new__(AutoRemediator)
        r._logged_unsupported_types = set()
        return r

    def test_secure_file_path_rejects_sibling_prefix_directory(self, tmp_path):
        """/repo-evil must not pass a boundary check for /repo.

        A symlink inside the repo resolves out to a sibling whose path shares
        the repo's string prefix, so the comparison has to be separator-aware
        (str.startswith(repo) alone would accept it).
        """
        from appsec_galaxy.auto_remediation.remediation import _secure_file_path
        repo = tmp_path / 'repo'
        repo.mkdir()
        sibling = tmp_path / 'repo-evil'
        sibling.mkdir()
        (sibling / 'app.py').write_text('x = 1\n')
        # Symlink avoids the '..' filter and still resolves outside the repo.
        (repo / 'link').symlink_to(sibling)

        assert _secure_file_path(str(repo), 'link/app.py') is None
        # A genuine in-repo file still resolves.
        (repo / 'real.py').write_text('x = 1\n')
        assert _secure_file_path(str(repo), 'real.py') is not None

    def test_package_name_with_leading_hyphen_rejected(self):
        """A package name from an untrusted manifest must never be parseable
        as a command-line flag."""
        from appsec_galaxy.auto_remediation.remediation import validate_package_name
        assert validate_package_name('lodash') is True
        assert validate_package_name('@scope/pkg') is True
        assert validate_package_name('-insecure') is False
        assert validate_package_name('--version') is False

    def test_default_branch_falls_back_on_hostile_refname(self, tmp_path, monkeypatch):
        """get_default_branch parses the scanned repo's own refs (untrusted)
        and feeds the result to `git checkout`."""
        import subprocess as sp
        from appsec_galaxy.auto_remediation import remediation as rm

        def fake_run(*args, **kwargs):
            out = Mock()
            out.stdout = 'refs/remotes/origin/--upload-pack=evil\n'
            out.returncode = 0
            return out

        monkeypatch.setattr(sp, 'run', fake_run)
        monkeypatch.setattr(rm.subprocess, 'run', fake_run)
        r = self._remediator()
        assert r.get_default_branch(str(tmp_path)) == 'main'

    def test_dependency_fix_rejects_traversal_path(self, tmp_path):
        repo = tmp_path / 'repo'
        repo.mkdir()
        # A real file outside the repo that the traversal targets.
        outside = tmp_path / 'requirements.txt'
        outside.write_text('flask==1.0\n')

        finding = {
            'path': '../requirements.txt', 'pkg_name': 'flask',
            'installed_version': '1.0', 'fixed_version': '2.0',
            'vulnerability_id': 'CVE-X',
        }
        result = self._remediator()._fix_dependency(finding, str(repo))

        assert result is None, 'traversal path must be rejected'
        # The load-bearing assertion: no backup write happened outside the repo.
        assert not (tmp_path / 'requirements.txt.backup').exists()
        assert outside.read_text() == 'flask==1.0\n', 'outside file must be untouched'

    def test_dependency_fix_rejects_absolute_escape(self, tmp_path):
        repo = tmp_path / 'repo'
        repo.mkdir()
        target = tmp_path / 'evil.txt'
        target.write_text('x')
        # os.path.join(repo, '/abs') discards the repo prefix entirely.
        finding = {
            'path': str(target), 'pkg_name': 'flask',
            'installed_version': '1.0', 'fixed_version': '2.0',
            'vulnerability_id': 'CVE-X',
        }
        result = self._remediator()._fix_dependency(finding, str(repo))
        assert result is None
        assert not (tmp_path / 'evil.txt.backup').exists()

    def test_apply_fix_rejects_traversal_path(self, tmp_path):
        repo = tmp_path / 'repo'
        repo.mkdir()
        outside = tmp_path / 'secret.py'
        outside.write_text('SAFE = 1\n')

        fix = {
            'file_path': '../secret.py', 'line_number': 1,
            'fixed_line': 'PWNED = 1',
        }
        ok = self._remediator().apply_fix(fix, str(repo))

        assert ok is False
        assert outside.read_text() == 'SAFE = 1\n', 'file outside repo must be untouched'

    def test_apply_fix_allows_in_repo_path(self, tmp_path):
        """The confinement must not break the normal in-repo case."""
        repo = tmp_path / 'repo'
        repo.mkdir()
        f = repo / 'app.py'
        f.write_text('x = 1\n')

        fix = {'file_path': 'app.py', 'line_number': 1, 'fixed_line': 'x = 2'}
        ok = self._remediator().apply_fix(fix, str(repo))

        assert ok is True
        assert f.read_text() == 'x = 2\n'

class TestUntrustedPRContext:
    """Auto-remediation must not run against fork PR code in CI, but must
    still run on same-repo PRs and pushes (src/main.py
    is_untrusted_pr_context + the CI gate in handle_auto_remediation)."""

    def _fn(self):
        if 'appsec_galaxy.main' in sys.modules:
            del sys.modules['appsec_galaxy.main']
        from appsec_galaxy import main as m
        return m.is_untrusted_pr_context

    def _event(self, tmp_path, fork, head='owner/app'):
        p = tmp_path / 'event.json'
        p.write_text(json.dumps({'pull_request': {'head': {'repo': {'fork': fork, 'full_name': head}}},
                                 'repository': {'full_name': 'owner/app'}}))
        return str(p)

    def test_fork_pr_is_untrusted(self, tmp_path, monkeypatch):
        monkeypatch.setenv('GITHUB_EVENT_NAME', 'pull_request')
        monkeypatch.setenv('GITHUB_REPOSITORY', 'owner/app')
        monkeypatch.setenv('GITHUB_EVENT_PATH', self._event(tmp_path, True, head='stranger/app'))
        assert self._fn()() is True

    def test_same_repo_pr_is_trusted(self, tmp_path, monkeypatch):
        monkeypatch.setenv('GITHUB_EVENT_NAME', 'pull_request')
        monkeypatch.setenv('GITHUB_REPOSITORY', 'owner/app')
        monkeypatch.setenv('GITHUB_EVENT_PATH', self._event(tmp_path, False))
        assert self._fn()() is False

    def test_same_repo_pr_in_a_forked_project_is_trusted(self, tmp_path, monkeypatch):
        """Regression: head.repo.fork is a property of the repository, so a
        project that was itself forked from a template had auto-fix silently
        disabled on every one of its own PRs."""
        monkeypatch.setenv('GITHUB_EVENT_NAME', 'pull_request')
        monkeypatch.setenv('GITHUB_REPOSITORY', 'owner/app')
        monkeypatch.setenv('GITHUB_EVENT_PATH', self._event(tmp_path, True, head='owner/app'))
        assert self._fn()() is False

    def test_pull_request_target_is_gated_too(self, tmp_path, monkeypatch):
        monkeypatch.setenv('GITHUB_EVENT_NAME', 'pull_request_target')
        monkeypatch.setenv('GITHUB_REPOSITORY', 'owner/app')
        monkeypatch.setenv('GITHUB_EVENT_PATH', self._event(tmp_path, True, head='stranger/app'))
        assert self._fn()() is True

    def test_pr_without_payload_fails_closed(self, monkeypatch):
        monkeypatch.setenv('GITHUB_EVENT_NAME', 'pull_request')
        monkeypatch.delenv('GITHUB_EVENT_PATH', raising=False)
        assert self._fn()() is True

    def test_push_event_is_trusted(self, monkeypatch):
        monkeypatch.setenv('GITHUB_EVENT_NAME', 'push')
        assert self._fn()() is False

    def test_no_ci_context_is_trusted(self, monkeypatch):
        monkeypatch.delenv('GITHUB_EVENT_NAME', raising=False)
        assert self._fn()() is False

    def test_gate_downgrades_autofix_on_fork_pr(self, tmp_path, monkeypatch, capsys):
        """On a fork PR, handle_auto_remediation must not create PRs even
        with APPSEC_AUTO_FIX=true."""
        if 'appsec_galaxy.main' in sys.modules:
            del sys.modules['appsec_galaxy.main']
        from appsec_galaxy import main as m
        monkeypatch.setenv('GITHUB_ACTIONS', 'true')
        monkeypatch.setenv('GITHUB_EVENT_NAME', 'pull_request')
        monkeypatch.setenv('GITHUB_REPOSITORY', 'owner/app')
        monkeypatch.setenv('GITHUB_EVENT_PATH', self._event(tmp_path, True, head='stranger/app'))
        monkeypatch.setenv('APPSEC_AUTO_FIX', 'true')
        monkeypatch.setenv('APPSEC_AUTO_FIX_MODE', '3')
        findings = [{'tool': 'semgrep', 'check_id': 'sqli', 'severity': 'high',
                     'path': 'a.py', 'start': {'line': 1}, 'extra': {'message': 'x'}}]
        # create_remediation_pr is the only path that commits/pushes/opens a
        # PR. Assert it is never reached on a fork PR.
        with patch('appsec_galaxy.auto_remediation.remediation.create_remediation_pr') as mock_pr:
            result = m.handle_auto_remediation('/tmp/repo', findings)
        assert not mock_pr.called, "remediation must not run on fork PRs"
        out = capsys.readouterr().out
        assert 'scanning only' in out.lower() or 'fork pull request' in out.lower()
        assert result is not None
