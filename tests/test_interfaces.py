"""
Machine-facing surfaces: the web API, the MCP server, the CI gate, and
the identity checks that keep prior branding out of the tree.
"""

import pytest
import codecs
import json
import subprocess
import os
from pathlib import Path
import sys
import tomllib




class TestWebAppSmoke:
    """Smoke tests for src/web_app.py Flask routes.

    These don't exercise scanning end-to-end (that requires real binaries
    and a real repo); they confirm routes return reasonable HTTP statuses
    and JSON shapes for the contracts the web UI depends on."""

    @pytest.fixture
    def client(self):
        if 'appsec_galaxy.web_app' in sys.modules:
            del sys.modules['appsec_galaxy.web_app']
        from appsec_galaxy import web_app
        web_app.app.config['TESTING'] = True
        return web_app.app.test_client()

    def test_health_endpoint_returns_200(self, client):
        response = client.get('/health')
        assert response.status_code == 200
        # Should be JSON
        assert response.is_json or response.content_type.startswith('application/json')

    def test_security_headers_present_on_every_response(self, client):
        """Baseline hardening headers, incl. a CSP: the report rendered from
        hostile scanned repos is served from this same origin."""
        response = client.get('/health')
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
        assert response.headers['X-Frame-Options'] == 'DENY'
        assert response.headers['Referrer-Policy'] == 'no-referrer'
        csp = response.headers['Content-Security-Policy']
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp

    def test_foreign_host_header_rejected_on_loopback_bind(self, client, monkeypatch):
        """DNS-rebinding guard: an attacker domain resolving to 127.0.0.1 must
        not be able to drive the API just because the bind is loopback."""
        monkeypatch.setenv('HOST', '127.0.0.1')
        assert client.get('/health', headers={'Host': 'evil.example.com'}).status_code == 400
        # Legitimate loopback hosts still work.
        assert client.get('/health', headers={'Host': 'localhost:8000'}).status_code == 200
        assert client.get('/health', headers={'Host': '127.0.0.1:8000'}).status_code == 200

    def test_foreign_host_allowed_when_bound_to_all_interfaces(self, client, monkeypatch):
        """An intentional 0.0.0.0 deployment is reached by hostname by design."""
        monkeypatch.setenv('HOST', '0.0.0.0')
        assert client.get('/health', headers={'Host': 'scanner.internal'}).status_code == 200

    def test_config_endpoint_returns_json(self, client):
        response = client.get('/config')
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, dict)

    def test_index_page_loads(self, client):
        """Root should return the upload page."""
        response = client.get('/')
        assert response.status_code == 200

    def test_scan_endpoint_rejects_missing_path(self, client):
        """POST /scan without a repo path should not 500; should 400."""
        response = client.post('/scan', json={})
        assert response.status_code in (400, 422)

    def test_scan_endpoint_rejects_path_traversal(self, client):
        """Repo-path validation should reject ../ traversal attempts."""
        response = client.post('/scan', json={'repo_path': '../../../etc/passwd'})
        assert response.status_code in (400, 403, 422)

    def test_config_reports_privacy_tier(self, client, monkeypatch):
        monkeypatch.setenv('APPSEC_AI_SCAN_TIER', '2')
        response = client.get('/config')
        assert response.status_code == 200
        assert response.get_json().get('ai_scan_tier') == '2'

    def test_scan_rejects_invalid_privacy_tier(self, client):
        response = client.post('/scan', json={
            'repo_path': '/tmp/repo', 'ai_scan_tier': '5',
        })
        assert response.status_code == 400
        assert 'ai_scan_tier' in response.get_json()['error']

    @pytest.mark.parametrize("body, needle", [
        ({'auto_fix': 'false'}, 'auto_fix must be a JSON boolean'),
        ({'auto_fix': True, 'auto_fix_mode': '9'}, 'auto_fix_mode'),
        ({'scan_level': 'high'}, 'scan_level'),
        ({'selected_tools': 'semgrep'}, 'selected_tools'),
    ])
    def test_scan_rejects_malformed_inputs(self, client, body, needle):
        """Regression: the string "false" is truthy, so auto_fix="false"
        committed, pushed, and opened PRs; an unknown scan_level made semgrep
        drop every finding (a clean-looking scan)."""
        response = client.post('/scan', json={'repo_path': '/tmp/repo', **body})
        assert response.status_code == 400
        assert needle in response.get_json()['error']

    def test_scan_rejects_ai_scan_at_low_tier(self, client):
        """The AI scanner sends full source; tiers 1 and 2 forbid that, so a
        request asking for both must fail fast, not silently skip the scan."""
        response = client.post('/scan', json={
            'repo_path': '/tmp/repo', 'ai_scan_tier': '2',
            'selected_tools': ['semgrep', 'ai_scan'],
        })
        assert response.status_code == 400
        assert 'privacy tier' in response.get_json()['error']

    def test_api_key_gates_sensitive_routes_only(self, monkeypatch, tmp_path):
        """With APPSEC_WEB_API_KEY set, scan and report routes need the header
        while /health stays open for liveness probes."""
        import sys
        monkeypatch.setenv('APPSEC_WEB_API_KEY', 'correct-horse')
        if 'appsec_galaxy.web_app' in sys.modules:
            del sys.modules['appsec_galaxy.web_app']
        from appsec_galaxy import web_app
        web_app.app.config['TESTING'] = True
        c = web_app.app.test_client()

        assert c.get('/health').status_code == 200
        assert c.post('/scan', json={'repo_path': str(tmp_path)}).status_code == 401
        assert c.post('/scan', json={'repo_path': str(tmp_path)},
                      headers={'X-API-Key': 'wrong'}).status_code == 401
        assert c.get('/report').status_code == 401
        # Correct key gets past auth (the request then fails on its own terms).
        assert c.get('/report', headers={'X-API-Key': 'correct-horse'}).status_code != 401

    @pytest.mark.parametrize("filename", [
        '../../../etc/passwd', 'evil.json', 'report.html', '.env', 'raw/gitleaks.json',
    ])
    def test_reports_route_serves_only_allowlisted_names(self, client, monkeypatch, tmp_path, filename):
        from appsec_galaxy import web_app
        monkeypatch.setattr(web_app, 'LAST_SCAN_OUTPUT_DIR', str(tmp_path), raising=False)
        assert client.get(f'/reports/{filename}').status_code in (403, 404)

    def test_browse_dir_requires_a_path_and_rejects_files(self, client, monkeypatch, tmp_path):
        monkeypatch.setenv('APPSEC_ENABLE_DIRECTORY_BROWSING', 'true')
        assert client.get('/browse-dir').status_code == 400
        target = tmp_path / 'a-file.txt'
        target.write_text('x')
        assert client.get(f'/browse-dir?path={target}').status_code == 400

    def test_browse_dir_is_off_by_default(self, client, monkeypatch, tmp_path):
        monkeypatch.delenv('APPSEC_ENABLE_DIRECTORY_BROWSING', raising=False)
        response = client.get(f'/browse-dir?path={tmp_path}')
        assert response.status_code == 403
        assert 'disabled' in response.get_json()['error']

    def test_report_route_404s_before_any_scan(self, client, monkeypatch):
        from appsec_galaxy import web_app
        monkeypatch.setattr(web_app, 'LAST_SCAN_OUTPUT_DIR', None, raising=False)
        assert client.get('/report').status_code == 404

    def test_unknown_route_returns_404(self, client):
        response = client.get('/this-route-does-not-exist-xyz')
        assert response.status_code == 404

    def test_scan_uses_key_rotated_in_dotenv_after_server_start(self, client, monkeypatch, tmp_path):
        """Regression: the server loaded .env once at startup, so replacing a
        revoked ANTHROPIC_API_KEY in .env kept producing "rejected the API
        key" until a restart. /scan must run its connection test with the
        key currently in .env."""
        import os
        from appsec_galaxy.scanners import ai_scanner
        env_file = tmp_path / '.env'
        env_file.write_text('ANTHROPIC_API_KEY=sk-ant-rotated-key\n')
        os.utime(env_file, (2_000, 2_000))
        monkeypatch.setattr(ai_scanner, '_dotenv_path', lambda: env_file)
        monkeypatch.setattr(ai_scanner, '_dotenv_seen_mtime', 1_000)
        monkeypatch.setenv('ANTHROPIC_API_KEY', 'sk-ant-revoked-key')
        monkeypatch.setenv('AI_PROVIDER', 'anthropic')
        ai_scanner.reset_ai_client_cache()

        seen: dict[str, str] = {}

        def fake_connection_test():
            seen['key'] = os.environ.get('ANTHROPIC_API_KEY', '')
            return False, 'stop here: connection test recorded the key'

        monkeypatch.setattr(ai_scanner, 'test_ai_connection', fake_connection_test)
        response = client.post('/scan', json={
            'repo_path': str(tmp_path), 'selected_tools': ['ai_scan'],
        })
        assert response.status_code == 400
        assert 'stop here' in response.get_json()['error']
        assert seen['key'] == 'sk-ant-rotated-key'

    def test_config_reports_key_rotated_in_dotenv_after_server_start(self, client, monkeypatch, tmp_path):
        """The provider dropdown's key status must reflect the current .env."""
        import os
        from appsec_galaxy.scanners import ai_scanner
        env_file = tmp_path / '.env'
        env_file.write_text('OPENAI_API_KEY=sk-openai-rotated-key\n')
        os.utime(env_file, (2_000, 2_000))
        monkeypatch.setattr(ai_scanner, '_dotenv_path', lambda: env_file)
        monkeypatch.setattr(ai_scanner, '_dotenv_seen_mtime', 1_000)
        monkeypatch.setenv('OPENAI_API_KEY', 'your-openai-api-key-here')

        response = client.get('/config')
        assert response.status_code == 200
        providers = {p['name']: p for p in response.get_json()['ai_providers']}
        assert providers['openai']['key_set'] is True

    def test_no_wildcard_cors_by_default(self, monkeypatch):
        """With no APPSEC_WEB_CORS_ORIGINS, responses must not carry
        Access-Control-Allow-Origin: * (a malicious site could otherwise
        script the local scanner)."""
        monkeypatch.delenv('APPSEC_WEB_CORS_ORIGINS', raising=False)
        if 'appsec_galaxy.web_app' in sys.modules:
            del sys.modules['appsec_galaxy.web_app']
        from appsec_galaxy import web_app
        web_app.app.config['TESTING'] = True
        client = web_app.app.test_client()
        resp = client.get('/health', headers={'Origin': 'http://evil.example'})
        assert resp.headers.get('Access-Control-Allow-Origin') != '*'
        assert 'Access-Control-Allow-Origin' not in resp.headers

class TestRepoDiscoveryScope:
    """Web discover-repos must default to ~/repos only; broader locations
    are opt-in via REPO_SEARCH_PATHS. Regression: Documents/Desktop/
    Downloads were searched by default and surfaced noise."""

    @pytest.fixture
    def client(self, monkeypatch, tmp_path):
        monkeypatch.setenv('APPSEC_ENABLE_DIRECTORY_BROWSING', 'true')
        monkeypatch.delenv('REPO_SEARCH_PATHS', raising=False)
        # Fake home with a repos dir and a noisy Documents dir
        (tmp_path / 'repos' / 'sandbox').mkdir(parents=True)
        (tmp_path / 'Documents' / 'TaxReturns2025').mkdir(parents=True)
        (tmp_path / 'Desktop' / 'RandomApp.app').mkdir(parents=True)
        from appsec_galaxy import web_app
        monkeypatch.setattr(web_app.Path, 'home', staticmethod(lambda: tmp_path))
        web_app.app.config['TESTING'] = True
        return web_app.app.test_client()

    def test_only_repos_dir_searched(self, client):
        resp = client.get('/discover-repos')
        assert resp.status_code == 200
        names = {r['name'] for r in resp.get_json()['repositories']}
        assert 'sandbox' in names
        assert 'TaxReturns2025' not in names
        assert 'RandomApp.app' not in names

    def test_custom_paths_extend_scope(self, client, monkeypatch, tmp_path):
        extra = tmp_path / 'elsewhere'
        (extra / 'special-repo').mkdir(parents=True)
        monkeypatch.setenv('REPO_SEARCH_PATHS', str(extra))
        resp = client.get('/discover-repos')
        names = {r['name'] for r in resp.get_json()['repositories']}
        assert 'special-repo' in names

    def test_disabled_returns_policy_error(self, client, monkeypatch):
        monkeypatch.setenv('APPSEC_ENABLE_DIRECTORY_BROWSING', 'false')
        resp = client.get('/discover-repos')
        assert resp.status_code == 403
        assert 'polic' in resp.get_json()['error'].lower()

class TestMCPServerInit:
    """Tests for AppSecGalaxyMCPCore init and installation discovery."""

    @pytest.fixture
    def mcp_module(self):
        """Import the MCP server module on demand."""
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'mcp'))
        # Force reimport so env var changes per-test are picked up
        if 'appsec_galaxy_mcp_server' in sys.modules:
            del sys.modules['appsec_galaxy_mcp_server']
        import appsec_galaxy_mcp_server
        return appsec_galaxy_mcp_server

    def test_init_finds_appsec_galaxy_via_path_env(self, mcp_module, tmp_path, monkeypatch):
        """APPSEC_GALAXY_PATH env var locates the install."""
        (tmp_path / "src" / "appsec_galaxy").mkdir(parents=True)
        (tmp_path / "src" / "appsec_galaxy" / "main.py").write_text("# fake")
        monkeypatch.setenv("APPSEC_GALAXY_PATH", str(tmp_path))

        core = mcp_module.AppSecGalaxyMCPCore()
        assert core.appsec_galaxy_path == str(tmp_path)

    def test_init_raises_when_no_install_found(self, mcp_module, tmp_path, monkeypatch):
        """If APPSEC_GALAXY_PATH is unset and no common location matches, raise a RuntimeError."""
        monkeypatch.delenv("APPSEC_GALAXY_PATH", raising=False)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            mcp_module.os.path,
            'dirname',
            lambda p: str(tmp_path / 'nowhere'),
        )
        monkeypatch.setattr(mcp_module.os.path, 'expanduser', lambda p: str(tmp_path / 'nowhere' / p.lstrip('~/')))

        with pytest.raises(RuntimeError) as exc_info:
            mcp_module.AppSecGalaxyMCPCore()
        assert "APPSEC_GALAXY_PATH" in str(exc_info.value)
        assert "AppSec Galaxy installation not found" in str(exc_info.value)

class TestMCPServerTools:
    """FastMCP tool registration and boundary validation. Verifies the MCP
    surface the server exposes hasn't drifted."""

    @pytest.fixture
    def mcp_module(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'mcp'))
        if 'appsec_galaxy_mcp_server' in sys.modules:
            del sys.modules['appsec_galaxy_mcp_server']
        import appsec_galaxy_mcp_server
        return appsec_galaxy_mcp_server

    def test_scan_subprocess_uses_safe_path(self, mcp_module, monkeypatch, tmp_path):
        """Regression: `python -m` with cwd=repo put the scanned repo first on
        sys.path, so a repo shipping dotenv/__init__.py ran its code inside
        the scanner (with provider keys in the environment). -P prevents it."""
        import threading
        core = mcp_module.AppSecGalaxyMCPCore.__new__(mcp_module.AppSecGalaxyMCPCore)
        core._active_scans = {}
        core._active_scans_lock = threading.Lock()
        core.is_scan_running = lambda p: False
        core._find_python_executable = lambda: '/usr/bin/python3'
        core._build_scan_env = lambda: {}
        captured = {}

        class FakeThread:
            def __init__(self, target=None, args=(), daemon=None):
                captured['cmd'] = args[1]

            def start(self):
                pass

        monkeypatch.setattr(mcp_module.threading, 'Thread', FakeThread)
        core.start_scan(str(tmp_path))
        assert captured['cmd'][:3] == ['/usr/bin/python3', '-P', '-m']

    def test_default_allowed_roots_exclude_home_and_cwd(self, mcp_module, monkeypatch):
        """Regression: "~" and "." were allowed roots, so the allowlist let a
        client scan ~/.ssh or wherever the server happened to start."""
        monkeypatch.delenv('APPSEC_MCP_ALLOWED_ROOTS', raising=False)
        monkeypatch.delenv('REPO_SEARCH_PATHS', raising=False)
        core = mcp_module.AppSecGalaxyMCPCore.__new__(mcp_module.AppSecGalaxyMCPCore)
        roots = core._find_repo_search_paths()
        home = os.path.expanduser('~')
        assert home not in roots and '.' not in roots
        assert all(r.startswith(home + os.sep) for r in roots)

    def test_fuzzy_match_never_resolves_dotfiles(self, mcp_module, monkeypatch, tmp_path):
        (tmp_path / '.aws').mkdir()
        monkeypatch.setenv('APPSEC_MCP_ALLOWED_ROOTS', str(tmp_path))
        core = mcp_module.AppSecGalaxyMCPCore.__new__(mcp_module.AppSecGalaxyMCPCore)
        with pytest.raises(ValueError):
            core.find_repo('aws')

    def test_gitleaks_normalizer_includes_confidence(self, mcp_module):
        f = mcp_module._normalize_gitleaks({'Description': 'key', 'RuleID': 'r',
                                            'File': 'a.py', 'StartLine': 1,
                                            'Secret': 'your-key-here'}, 0)
        assert f['confidence'] == 'low'
        assert 'your-key-here' not in f['confidence_reason']

    def test_iter_trivy_findings_includes_misconfigs(self, mcp_module, sample_trivy_misconfig_output):
        """MCP must surface Misconfigurations, not just Vulnerabilities."""
        data = {
            "Results": sample_trivy_misconfig_output["Results"] + [{
                "Target": "package-lock.json",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2021-23337", "PkgName": "lodash",
                    "InstalledVersion": "4.17.19", "FixedVersion": "4.17.21",
                    "Severity": "HIGH", "Title": "Command Injection",
                }],
            }],
        }
        findings = mcp_module._iter_trivy_findings(data)
        assert len(findings) == 2
        misconf = next(f for f in findings if f.get('finding_type') == 'misconfiguration')
        assert misconf['vulnerability_id'] == 'DS002'
        assert misconf['file_path'] == 'Dockerfile'
        assert misconf['line_start'] == 1
        assert misconf['severity'] == 'high'
        assert misconf['remediation'].startswith("Add 'USER")
        vuln = next(f for f in findings if 'finding_type' not in f)
        assert vuln['package_name'] == 'lodash'

    def test_all_16_tools_registered(self, mcp_module):
        """The 16 tools the README advertises must be registered on FastMCP."""
        import asyncio
        tools = asyncio.run(mcp_module.mcp_app.list_tools())
        tool_names = {t.name for t in tools}
        expected = {
            "scan_repository", "auto_remediate", "get_report", "generate_sbom",
            "cross_file_analysis", "assess_business_impact", "view_report_html",
            "get_scan_findings", "get_semgrep_findings", "get_trivy_findings",
            "get_gitleaks_findings", "get_code_quality_findings", "get_sbom_data",
            "health_check", "analyze_dependency_health", "get_dependency_usage",
        }
        assert expected == tool_names, f"Tool drift: missing={expected - tool_names}, extra={tool_names - expected}"

    def test_server_identity(self, mcp_module):
        assert mcp_module.SERVER_NAME == "appsec-galaxy"
        assert mcp_module.AppSecGalaxyMCPCore.__name__ == "AppSecGalaxyMCPCore"

    def test_import_and_initialize_without_openai_key(self):
        root = Path(__file__).resolve().parent.parent
        server = root / "mcp" / "appsec_galaxy_mcp_server.py"
        env = os.environ.copy()
        env.pop("OPENAI_API_KEY", None)
        env["APPSEC_GALAXY_PATH"] = str(root)
        env["PYTHONPATH"] = str(root / "src")
        code = (
            "import importlib.util; "
            f"p={str(server)!r}; "
            "s=importlib.util.spec_from_file_location('appsec_galaxy_mcp_server', p); "
            "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
            "m.AppSecGalaxyMCPCore(); print(m.SERVER_NAME)"
        )

        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )

        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "appsec-galaxy"

    def test_tools_have_generated_schemas(self, mcp_module):
        """FastMCP must generate an input schema requiring repo_path."""
        import asyncio
        tools = asyncio.run(mcp_module.mcp_app.list_tools())
        by_name = {t.name: t for t in tools}
        schema = by_name["scan_repository"].inputSchema
        assert "repo_path" in schema.get("properties", {})
        assert "repo_path" in schema.get("required", [])

    def test_validate_repo_arg_rejects_shell_metacharacters(self, mcp_module):
        """Boundary validation must reject injection attempts before discovery."""
        for hostile in ("repo; rm -rf /", "repo | cat /etc/passwd", "repo`id`",
                        "repo$(id)", "repo\x00", "repo\nmalicious"):
            with pytest.raises(ValueError):
                mcp_module._validate_repo_arg(hostile)

    def test_validate_repo_arg_rejects_empty_and_oversized(self, mcp_module):
        with pytest.raises(ValueError):
            mcp_module._validate_repo_arg("")
        with pytest.raises(ValueError):
            mcp_module._validate_repo_arg("x" * 5000)

    def test_validate_repo_arg_accepts_normal_paths(self, mcp_module):
        assert mcp_module._validate_repo_arg("nodejs-goof") == "nodejs-goof"
        assert mcp_module._validate_repo_arg("/Users/me/repos/app") == "/Users/me/repos/app"

    def test_combined_and_gitleaks_findings_never_return_secret_value(
        self, mcp_module, monkeypatch, tmp_path
    ):
        sentinel = "SYNTHETIC_SECRET_VALUE"
        raw = tmp_path / "raw"
        raw.mkdir()
        (raw / "gitleaks.json").write_text(json.dumps([{
            "RuleID": "generic-secret",
            "Description": "Synthetic fixture",
            "File": "config.py",
            "StartLine": 7,
            "EndLine": 7,
            "Secret": sentinel,
        }]))

        class StubCore:
            def find_repo(self, repo_path):
                return str(tmp_path)

            def is_scan_running(self, repo_path):
                return False

            def raw_dir(self, repo_path):
                return str(raw)

            def _load_json(self, path):
                path = Path(path)
                return json.loads(path.read_text()) if path.exists() else None

        monkeypatch.setattr(mcp_module, "_core", lambda: StubCore())

        assert sentinel not in mcp_module.get_scan_findings(str(tmp_path))
        assert sentinel not in mcp_module.get_gitleaks_findings(str(tmp_path))

    def test_dependency_tools_use_packaged_analyzer(self, mcp_module, monkeypatch, tmp_path):
        from types import SimpleNamespace
        from appsec_galaxy import dependency_analyzer

        dependency = SimpleNamespace(
            package_name="requests",
            ecosystem="pypi",
            installed_version="2.0",
            manifest_file="requirements.txt",
            health_status="healthy",
            depth_score=2,
            depth_category="shallow",
            remediation_strategy="keep",
            replacement_suggestion="",
            has_cve=False,
            fixed_version="",
            files_using={"app.py"},
            unique_apis_used={"get"},
            import_sites=[],
            call_sites=[],
            health_info={},
        )
        report = SimpleNamespace(
            analyzed_dependencies=1,
            total_dependencies=1,
            health_breakdown={"healthy": 1},
            depth_breakdown={"shallow": 1},
            strategy_breakdown={"keep": 1},
            dependencies=[dependency],
        )
        monkeypatch.setattr(dependency_analyzer, "run_dependency_analysis", lambda path: report)
        monkeypatch.setattr(mcp_module, "_resolve", lambda path: str(tmp_path))

        assert "Dependency Health Report" in mcp_module.analyze_dependency_health(str(tmp_path))
        assert "requests" in mcp_module.get_dependency_usage(str(tmp_path), "requests")

class TestMCPResources:
    """FastMCP resources exposing scan artifacts."""

    @pytest.fixture
    def mcp_module(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'mcp'))
        if 'appsec_galaxy_mcp_server' in sys.modules:
            del sys.modules['appsec_galaxy_mcp_server']
        import appsec_galaxy_mcp_server
        return appsec_galaxy_mcp_server

    def test_resource_templates_registered(self, mcp_module):
        import asyncio
        templates = asyncio.run(mcp_module.mcp_app.list_resource_templates())
        uris = {str(t.uriTemplate) for t in templates}
        assert 'appsec-galaxy://{repo}/report.html' in uris
        assert 'appsec-galaxy://{repo}/report.sarif' in uris
        assert 'appsec-galaxy://{repo}/sbom.cyclonedx.json' in uris
        assert 'appsec-galaxy://{repo}/sbom.spdx.json' in uris

    def test_read_artifact_returns_content(self, mcp_module, tmp_path, monkeypatch):
        (tmp_path / 'report.sarif').write_text('{"version": "2.1.0"}')

        class StubCore:
            def find_repo(self, p):
                return str(tmp_path)
            def _get_repo_output_path(self, p):
                return str(tmp_path)
        monkeypatch.setattr(mcp_module, '_core', lambda: StubCore())
        content = mcp_module._read_artifact('myrepo', 'report.sarif', 'SARIF report')
        assert '2.1.0' in content

    def test_read_artifact_missing_file_message(self, mcp_module, tmp_path, monkeypatch):
        class StubCore:
            def find_repo(self, p):
                return str(tmp_path)
            def _get_repo_output_path(self, p):
                return str(tmp_path)
        monkeypatch.setattr(mcp_module, '_core', lambda: StubCore())
        msg = mcp_module._read_artifact('myrepo', 'report.html', 'HTML report')
        assert 'scan_repository' in msg

    def test_read_artifact_validates_input(self, mcp_module):
        with pytest.raises(ValueError):
            mcp_module._read_artifact('bad; rm -rf /', 'report.html', 'HTML report')

class TestFailOnCritical:
    """Tests for the post-scan gate that fails CI when critical findings land.

    The script lives at scripts/fail_on_critical.py and reads outputs/raw/*.json.
    Each test creates a temp working directory with a controlled outputs/raw/
    layout, runs the script as a subprocess, and asserts the exit code."""

    @pytest.fixture
    def script_path(self):
        return Path(__file__).resolve().parent.parent / 'scripts' / 'fail_on_critical.py'

    def _run(self, tmp_path, script_path, env_extra=None):
        """Run the script in tmp_path with optional env vars; return (exitcode, stdout)."""
        env = os.environ.copy()
        env['GITHUB_WORKSPACE'] = str(tmp_path)  # gate reads .appsec-galaxy-ignore from here
        if env_extra:
            env.update(env_extra)
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(tmp_path),
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode, result.stdout

    def _write_raw(self, tmp_path, **scanner_payloads):
        raw = tmp_path / 'outputs' / 'raw'
        raw.mkdir(parents=True, exist_ok=True)
        for name, payload in scanner_payloads.items():
            (raw / f'{name}.json').write_text(json.dumps(payload))

    def test_no_outputs_dir_passes(self, tmp_path, script_path):
        """No outputs/raw/ directory: script should pass (graceful skip)."""
        code, _ = self._run(tmp_path, script_path)
        assert code == 0

    def test_empty_raw_dir_passes(self, tmp_path, script_path):
        """outputs/raw/ exists but no scanner files: script should pass."""
        (tmp_path / 'outputs' / 'raw').mkdir(parents=True)
        code, _ = self._run(tmp_path, script_path)
        assert code == 0

    def test_clean_scan_passes(self, tmp_path, script_path):
        """All scanner files present but contain no critical findings: pass."""
        self._write_raw(
            tmp_path,
            semgrep={'results': [{'extra': {'severity': 'INFO'}}]},
            trivy={'Results': [{'Vulnerabilities': [{'Severity': 'LOW'}]}]},
            gitleaks=[],
        )
        code, _ = self._run(tmp_path, script_path)
        assert code == 0

    def test_semgrep_critical_fails(self, tmp_path, script_path):
        """Semgrep finding with severity=critical: fail."""
        self._write_raw(
            tmp_path,
            semgrep={'results': [{'extra': {'severity': 'CRITICAL'}}]},
        )
        code, stdout = self._run(tmp_path, script_path)
        assert code == 1
        assert 'Failing the build' in stdout

    def test_trivy_critical_cve_fails(self, tmp_path, script_path):
        """Trivy CVE with Severity=CRITICAL: fail."""
        self._write_raw(
            tmp_path,
            trivy={'Results': [{'Vulnerabilities': [{'Severity': 'CRITICAL'}]}]},
        )
        code, _ = self._run(tmp_path, script_path)
        assert code == 1

    def test_trivy_critical_misconfig_fails(self, tmp_path, script_path):
        """Trivy IaC misconfiguration with Severity=CRITICAL: fail."""
        self._write_raw(
            tmp_path,
            trivy={'Results': [{'Target': 'Dockerfile',
                                'Misconfigurations': [{'ID': 'DS002', 'Severity': 'CRITICAL'}]}]},
        )
        code, stdout = self._run(tmp_path, script_path)
        assert code == 1
        assert 'Trivy     : 1' in stdout

    def test_suppressed_misconfig_passes(self, tmp_path, script_path):
        """.appsec-galaxy-ignore suppression matches misconfig IDs too."""
        (tmp_path / '.appsec-galaxy-ignore').write_text('trivy:DS002:*\n')
        self._write_raw(
            tmp_path,
            trivy={'Results': [{'Target': 'Dockerfile',
                                'Misconfigurations': [{'ID': 'DS002', 'Severity': 'CRITICAL'}]}]},
        )
        code, _ = self._run(tmp_path, script_path)
        assert code == 0

    def test_gitleaks_any_leak_fails(self, tmp_path, script_path):
        """Any gitleaks finding is treated as critical: fail."""
        self._write_raw(
            tmp_path,
            gitleaks=[{'Description': 'AWS key found', 'File': 'secrets.env'}],
        )
        code, _ = self._run(tmp_path, script_path)
        assert code == 1

    def test_threshold_critical_ignores_high(self, tmp_path, script_path):
        """Default threshold=critical should NOT fail on HIGH-only findings."""
        self._write_raw(
            tmp_path,
            semgrep={'results': [{'extra': {'severity': 'ERROR'}}]},  # ERROR maps to high
            trivy={'Results': [{'Vulnerabilities': [{'Severity': 'HIGH'}]}]},
        )
        code, _ = self._run(tmp_path, script_path)
        assert code == 0

    def test_threshold_high_catches_high(self, tmp_path, script_path):
        """Threshold=high should fail on HIGH (and CRITICAL) findings."""
        self._write_raw(
            tmp_path,
            trivy={'Results': [{'Vulnerabilities': [{'Severity': 'HIGH'}]}]},
        )
        code, _ = self._run(tmp_path, script_path, env_extra={'APPSEC_FAIL_THRESHOLD': 'high'})
        assert code == 1

    def test_invalid_json_does_not_crash(self, tmp_path, script_path):
        """Malformed JSON in a scanner file should not raise; treat as no findings."""
        raw = tmp_path / 'outputs' / 'raw'
        raw.mkdir(parents=True)
        (raw / 'semgrep.json').write_text('not valid json {{{')
        code, _ = self._run(tmp_path, script_path)
        assert code == 0

class TestFailOnCriticalPathResolution:
    """Regression tests: the gate must find outputs/<repo>/raw/ (the layout
    AppSec Galaxy actually writes) and the trivy-sca.json filename. Before this fix
    the gate silently exited 0 in CI because it only checked outputs/raw/
    and trivy.json, neither of which exist."""

    @pytest.fixture
    def script_path(self):
        return Path(__file__).resolve().parent.parent / 'scripts' / 'fail_on_critical.py'

    def _run(self, tmp_path, script_path, env_extra=None):
        env = os.environ.copy()
        env['GITHUB_WORKSPACE'] = str(tmp_path)  # gate reads .appsec-galaxy-ignore from here
        if env_extra:
            env.update(env_extra)
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(tmp_path), env=env, capture_output=True, text=True, timeout=10,
        )
        return result.returncode, result.stdout

    def test_finds_repo_namespaced_raw_dir(self, tmp_path, script_path):
        """Critical semgrep finding under outputs/<repo>/raw/ must fail the build."""
        raw = tmp_path / 'outputs' / 'myrepo' / 'raw'
        raw.mkdir(parents=True)
        (raw / 'semgrep.json').write_text(json.dumps(
            {'results': [{'extra': {'severity': 'CRITICAL'}}]}))
        code, out = self._run(tmp_path, script_path)
        assert code == 1
        assert 'Failing the build' in out

    def test_reads_trivy_sca_filename(self, tmp_path, script_path):
        """trivy-sca.json (the name the scanner writes) must be counted."""
        raw = tmp_path / 'outputs' / 'myrepo' / 'raw'
        raw.mkdir(parents=True)
        (raw / 'trivy-sca.json').write_text(json.dumps(
            {'Results': [{'Vulnerabilities': [{'Severity': 'CRITICAL'}]}]}))
        code, out = self._run(tmp_path, script_path)
        assert code == 1

    def test_legacy_flat_layout_still_works(self, tmp_path, script_path):
        raw = tmp_path / 'outputs' / 'raw'
        raw.mkdir(parents=True)
        (raw / 'gitleaks.json').write_text(json.dumps([{'RuleID': 'aws-key'}]))
        code, _ = self._run(tmp_path, script_path)
        assert code == 1

    def test_no_outputs_at_all_passes(self, tmp_path, script_path):
        code, out = self._run(tmp_path, script_path)
        assert code == 0
        assert 'skipping' in out

class TestFailOnCriticalHonorsBaseline:
    """The CI gate must apply .appsec-galaxy-ignore, same as the scan pipeline.
    Regression for the self-scan failing on our own test fixtures."""

    @pytest.fixture
    def script_path(self):
        return Path(__file__).resolve().parent.parent / 'scripts' / 'fail_on_critical.py'

    def _run(self, tmp_path, script_path):
        env = os.environ.copy()
        env['GITHUB_WORKSPACE'] = str(tmp_path)  # gate reads .appsec-galaxy-ignore from here
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(tmp_path), env=env, capture_output=True, text=True, timeout=10,
        )
        return result.returncode, result.stdout

    def _write_gitleaks(self, tmp_path, leaks):
        raw = tmp_path / 'outputs' / 'appsec-galaxy' / 'raw'
        raw.mkdir(parents=True)
        (raw / 'gitleaks.json').write_text(json.dumps(leaks))

    def test_suppressed_leaks_pass_the_gate(self, tmp_path, script_path):
        (tmp_path / '.appsec-galaxy-ignore').write_text("gitleaks:*:tests/*\n")
        self._write_gitleaks(tmp_path, [
            {'RuleID': 'hardcoded-password', 'File': 'tests/conftest.py'},
            {'RuleID': 'generic-secret', 'File': 'tests/test_appsec_galaxy.py'},
        ])
        code, out = self._run(tmp_path, script_path)
        assert code == 0, out
        assert 'Build passes' in out

    def test_unsuppressed_leaks_still_fail(self, tmp_path, script_path):
        (tmp_path / '.appsec-galaxy-ignore').write_text("gitleaks:*:tests/*\n")
        self._write_gitleaks(tmp_path, [
            {'RuleID': 'hardcoded-password', 'File': 'tests/conftest.py'},  # suppressed
            {'RuleID': 'aws-access-key', 'File': 'src/config.py'},          # real
        ])
        code, out = self._run(tmp_path, script_path)
        assert code == 1
        assert 'Gitleaks  : 1' in out

    def test_no_ignore_file_gate_stays_strict(self, tmp_path, script_path):
        self._write_gitleaks(tmp_path, [{'RuleID': 'x', 'File': 'tests/a.py'}])
        code, _ = self._run(tmp_path, script_path)
        assert code == 1

class TestGateWorkspaceResolution:
    """Composite-action scenario: gate cwd is the AppSec Galaxy checkout while the
    scanned repo (GITHUB_WORKSPACE) holds .appsec-galaxy-ignore."""

    @pytest.fixture
    def script_path(self):
        return Path(__file__).resolve().parent.parent / 'scripts' / 'fail_on_critical.py'

    def test_baseline_read_from_workspace_not_cwd(self, tmp_path, script_path):
        """Composite-action scenario: gate runs from the AppSec Galaxy checkout (cwd)
        while the scanned repo (GITHUB_WORKSPACE) holds .appsec-galaxy-ignore."""
        workspace = tmp_path / 'client-repo'
        workspace.mkdir()
        (workspace / '.appsec-galaxy-ignore').write_text("gitleaks:*:tests/*\n")
        action_dir = tmp_path / 'appsec-galaxy-action'
        raw = action_dir / 'outputs' / 'client-repo' / 'raw'
        raw.mkdir(parents=True)
        (raw / 'gitleaks.json').write_text(json.dumps(
            [{'RuleID': 'hardcoded-password', 'File': 'tests/conftest.py'}]))

        env = os.environ.copy()
        env['GITHUB_WORKSPACE'] = str(workspace)
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(action_dir), env=env, capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, result.stdout

class TestMachineFacingIdentity:
    """Action, workflow, MCP config, and baseline identity contracts."""

    @pytest.fixture
    def root(self):
        return Path(__file__).resolve().parent.parent

    def test_action_supports_both_providers(self, root):
        source = (root / 'action.yml').read_text()
        assert source.startswith(
            "name: 'AppSec Galaxy Scan'\n"
            "description: 'AI-powered application security scanning with cross-file attack-chain analysis'\n"
            "author: 'AppSec Galaxy Contributors'\n"
        )
        assert 'ai-provider:' in source
        assert "default: 'anthropic'" in source
        assert 'openai-api-key:' in source
        assert 'anthropic-api-key:' in source
        assert 'ai-model:' in source
        assert 'AI_PROVIDER: ${{ inputs.ai-provider }}' in source
        assert 'OPENAI_API_KEY: ${{ inputs.openai-api-key }}' in source
        assert 'ANTHROPIC_API_KEY: ${{ inputs.anthropic-api-key }}' in source
        assert 'AI_MODEL: ${{ inputs.ai-model }}' in source
        # rot13-encoded so the banned identities never appear in the tree,
        # not even as recognizable fragments.
        for encoded in ('orqebpx', 'njf-npprff-xrl', 'vasrerapr-cebsvyr', 'grxfgernz'):
            legacy = codecs.decode(encoded, 'rot13')
            assert legacy not in source.lower()

    def test_workflow_quality_gates_and_ai_free_self_scan(self, root):
        tests_workflow = (root / '.github' / 'workflows' / 'tests.yml').read_text()
        self_scan = (root / '.github' / 'workflows' / 'self-scan.yml').read_text()
        assert 'ruff check src/ mcp/ scripts/ tests/' in tests_workflow
        assert 'mypy src/appsec_galaxy mcp scripts tests' in tests_workflow
        assert 'pytest tests/ -v --tb=short' in tests_workflow
        # The self-scan is rule-based only: AI off, no provider secrets,
        # no scheduled runs, zero API spend.
        assert 'APPSEC_AI_SCAN: "false"' in self_scan
        assert 'secrets.OPENAI_API_KEY' not in self_scan
        assert '\n  schedule:' not in self_scan
        assert 'APPSEC_AUTO_FIX: "false"' in self_scan
        assert 'APPSEC_AUTO_FIX_MODE: "4"' in self_scan
        # rot13-encoded banned identities (see note in the action test above)
        for encoded in ('naguebcvp', 'orqebpx', 'vevf'):
            legacy = codecs.decode(encoded, 'rot13')
            assert legacy not in (tests_workflow + self_scan).lower()

    def test_codex_mcp_config_has_no_embedded_environment(self, root):
        # .codex/ is gitignored local tooling; the file exists only on dev
        # machines. When present it must stay credential-free.
        config_path = root / '.codex' / 'config.toml'
        if not config_path.exists():
            pytest.skip('.codex/config.toml is local-only and absent here')
        source = config_path.read_text()
        config = tomllib.loads(source)
        server = config['mcp_servers']['appsec-galaxy']
        assert '[mcp_servers.appsec-galaxy]' in source
        assert server == {
            'command': '.venv/bin/python',
            'args': ['mcp/appsec_galaxy_mcp_server.py'],
        }

    def test_baseline_filename_is_appsec_galaxy_only(self, root):
        source = '\n'.join(
            (root / path).read_text()
            for path in (
                'src/appsec_galaxy/scan_filters.py',
                'scripts/fail_on_critical.py',
                'action.yml',
            )
        )
        assert '.appsec-galaxy-ignore' in source
        assert codecs.decode('.vevf-vtaber', 'rot13') not in source
        assert (root / '.appsec-galaxy-ignore').is_file()
        assert not (root / codecs.decode('.vevf-vtaber', 'rot13')).exists()

def test_web_images_route_serves_checkout_asset():
    from appsec_galaxy.web_app import app

    response = app.test_client().get("/images/web.png")

    assert response.status_code == 200
    assert response.mimetype == "image/png"
