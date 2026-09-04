"""
Report surfaces: the HTML executive summary, SARIF export, markdown
rendering, and the shared summary statistics.
"""

import pytest
import json
import re
from pathlib import Path
import sys




class TestMarkdownToHtml:
    """Tests for _markdown_to_html used in executive summary rendering."""

    def test_bold_converted(self):
        from appsec_galaxy.reporting.ai_summary import _markdown_to_html
        result = _markdown_to_html("This is **critical** risk")
        assert '<strong>critical</strong>' in result
        assert '**' not in result

    def test_headers_converted(self):
        from appsec_galaxy.reporting.ai_summary import _markdown_to_html
        result = _markdown_to_html("# Risk Overview\nSome text")
        assert '<h3' in result
        assert 'Risk Overview' in result
        assert '#' not in result.replace('</h3>', '').replace('</h4>', '').split('Risk Overview')[0]

    def test_html_escaped(self):
        from appsec_galaxy.reporting.ai_summary import _markdown_to_html
        result = _markdown_to_html("XSS via <script>alert(1)</script>")
        assert '<script>' not in result
        assert '&lt;script&gt;' in result

    def test_bullet_list(self):
        from appsec_galaxy.reporting.ai_summary import _markdown_to_html
        result = _markdown_to_html("- Fix SQL injection\n- Rotate secrets")
        assert '<li>' in result
        assert '<ul' in result

    def test_bullet_list_has_no_br_between_items(self):
        """Regression: list items used to be separated by <br>, which browsers
        rendered as huge blank gaps between bullets. The exec summary in the
        nodejs-goof report looked broken because of this."""
        from appsec_galaxy.reporting.ai_summary import _markdown_to_html
        md = "Actions:\n\n- First\n- Second\n- Third\n"
        result = _markdown_to_html(md)
        # Isolate the <ul>...</ul> block and assert no <br> survived inside it.
        ul_block = result.split('<ul')[1].split('</ul>')[0]
        assert '<br>' not in ul_block, (
            f"<br> leaked into list block, will render as blank-line gaps: {ul_block!r}"
        )

    def test_ul_not_wrapped_in_paragraph(self):
        """Regression: <ul> used to be emitted inside <p>...</p>, which is
        invalid HTML (block inside inline) and made browsers auto-close the
        <p> at unpredictable spots. The result must keep <ul> as a top-level
        sibling, not a child of <p>."""
        from appsec_galaxy.reporting.ai_summary import _markdown_to_html
        md = "Header text\n\n- Item A\n- Item B\n"
        result = _markdown_to_html(md)
        # The pathological pattern is `<p>...<ul>`; tolerate whitespace.
        import re as _re
        assert not _re.search(r'<p[^>]*>\s*<ul', result), (
            f"<ul> is nested inside <p>, which is invalid HTML: {result!r}"
        )

class TestSarifExport:
    """SARIF 2.1.0 exporter (src/reporting/sarif.py)."""

    def _sample_findings(self):
        return [
            {'tool': 'semgrep', 'check_id': 'js.sqli', 'path': '/repo/app.js',
             'start': {'line': 10}, 'extra': {'message': 'SQL injection'}, 'severity': 'critical'},
            {'tool': 'gitleaks', 'RuleID': 'aws-key', 'File': 'config.py',
             'StartLine': 2, 'Description': 'AWS key'},
            {'tool': 'trivy', 'vulnerability_id': 'CVE-2021-23337', 'path': 'package-lock.json',
             'line': 1, 'description': 'lodash cmd injection', 'severity': 'high',
             'epss_score': 0.42, 'in_kev': True, 'exploit_priority': 'urgent'},
            {'tool': 'pylint', 'check_id': 'W0611', 'path': 'x.py',
             'start': {'line': 5}, 'extra': {'message': 'unused import'},
             'severity': 'low', 'category': 'code_quality'},
        ]

    def test_valid_sarif_structure(self):
        from appsec_galaxy.reporting.sarif import findings_to_sarif
        sarif = findings_to_sarif(self._sample_findings(), '/repo')
        assert sarif['version'] == '2.1.0'
        run = sarif['runs'][0]
        assert run['tool']['driver']['name'] == 'AppSec Galaxy'
        assert len(run['results']) == 4
        assert len(run['tool']['driver']['rules']) == 4

    def test_severity_level_mapping(self):
        from appsec_galaxy.reporting.sarif import findings_to_sarif
        results = findings_to_sarif(self._sample_findings(), '/repo')['runs'][0]['results']
        levels = {r['ruleId']: r['level'] for r in results}
        assert levels['js.sqli'] == 'error'       # critical
        assert levels['aws-key'] == 'error'       # secrets are critical
        assert levels['CVE-2021-23337'] == 'error'  # high
        assert levels['W0611'] == 'note'          # low

    def test_repo_relative_uris(self):
        from appsec_galaxy.reporting.sarif import findings_to_sarif
        results = findings_to_sarif(self._sample_findings(), '/repo')['runs'][0]['results']
        uris = {r['locations'][0]['physicalLocation']['artifactLocation']['uri'] for r in results}
        assert 'app.js' in uris  # /repo/app.js made relative
        assert 'config.py' in uris

    def test_exploit_intel_carried_in_properties(self):
        from appsec_galaxy.reporting.sarif import findings_to_sarif
        results = findings_to_sarif(self._sample_findings(), '/repo')['runs'][0]['results']
        trivy = next(r for r in results if r['ruleId'] == 'CVE-2021-23337')
        assert trivy['properties']['in_kev'] is True
        assert trivy['properties']['epss_score'] == 0.42

    def test_rules_deduplicated(self):
        from appsec_galaxy.reporting.sarif import findings_to_sarif
        f = {'tool': 'semgrep', 'check_id': 'dup', 'path': 'a.py',
             'start': {'line': 1}, 'extra': {'message': 'm'}, 'severity': 'high'}
        sarif = findings_to_sarif([f, dict(f), dict(f)], '')
        assert len(sarif['runs'][0]['tool']['driver']['rules']) == 1
        assert len(sarif['runs'][0]['results']) == 3

    def test_security_severity_on_rules(self):
        """GitHub's Security tab ranks by rule security-severity, not level."""
        from appsec_galaxy.reporting.sarif import findings_to_sarif
        rules = findings_to_sarif(self._sample_findings(), '/repo')['runs'][0]['tool']['driver']['rules']
        sev = {r['id']: r['properties']['security-severity'] for r in rules}
        assert sev['js.sqli'] == '9.5'           # critical
        assert sev['aws-key'] == '9.5'           # secrets default critical
        assert sev['CVE-2021-23337'] == '8.0'    # high
        assert sev['W0611'] == '3.0'             # low

    def test_partial_fingerprints_stable_and_distinct(self):
        """Fingerprints let GitHub dedup alerts across runs: identical
        findings hash identically, different findings differently."""
        from appsec_galaxy.reporting.sarif import findings_to_sarif
        results = findings_to_sarif(self._sample_findings(), '/repo')['runs'][0]['results']
        hashes = [r['partialFingerprints']['appsecGalaxy/v1'] for r in results]
        assert all(len(h) == 64 and int(h, 16) >= 0 for h in hashes)
        assert len(set(hashes)) == len(hashes)  # distinct findings, distinct hashes
        rerun = findings_to_sarif(self._sample_findings(), '/repo')['runs'][0]['results']
        assert [r['partialFingerprints']['appsecGalaxy/v1'] for r in rerun] == hashes

    def test_fingerprint_prefers_snippet_over_line(self):
        """Same snippet moved to a new line must keep its fingerprint."""
        from appsec_galaxy.reporting.sarif import findings_to_sarif
        f1 = {'tool': 'semgrep', 'check_id': 'sqli', 'path': 'a.py',
              'start': {'line': 10}, 'extra': {'message': 'm', 'lines': 'db.query(x)'}, 'severity': 'high'}
        f2 = {**f1, 'start': {'line': 55}}
        h = [r['partialFingerprints']['appsecGalaxy/v1']
             for r in findings_to_sarif([f1, f2], '')['runs'][0]['results']]
        assert h[0] == h[1]

    def test_help_uri_from_source_tool(self):
        from appsec_galaxy.reporting.sarif import findings_to_sarif
        semgrep = {'tool': 'semgrep', 'check_id': 'sqli', 'path': 'a.py', 'start': {'line': 1},
                   'extra': {'message': 'm', 'metadata': {'source': 'https://semgrep.dev/r/sqli'}},
                   'severity': 'high'}
        trivy = {'tool': 'trivy', 'vulnerability_id': 'CVE-1', 'path': 'lock', 'line': 1,
                 'description': 'd', 'severity': 'high',
                 'references': ['https://avd.aquasec.com/nvd/cve-1']}
        no_uri = {'tool': 'gitleaks', 'RuleID': 'aws-key', 'File': 'c.py', 'StartLine': 1,
                  'Description': 'AWS key'}
        rules = {r['id']: r for r in
                 findings_to_sarif([semgrep, trivy, no_uri], '')['runs'][0]['tool']['driver']['rules']}
        assert rules['sqli']['helpUri'] == 'https://semgrep.dev/r/sqli'
        assert rules['CVE-1']['helpUri'] == 'https://avd.aquasec.com/nvd/cve-1'
        assert 'helpUri' not in rules['aws-key']

    def test_generate_writes_file(self, tmp_path):
        from appsec_galaxy.reporting.sarif import generate_sarif_report
        out = generate_sarif_report(self._sample_findings(), tmp_path, '/repo')
        assert out is not None and out.exists()
        data = json.loads(out.read_text())
        assert data['version'] == '2.1.0'

    def test_empty_findings_still_valid(self, tmp_path):
        from appsec_galaxy.reporting.sarif import generate_sarif_report
        out = generate_sarif_report([], tmp_path)
        data = json.loads(out.read_text())
        assert data['runs'][0]['results'] == []

class TestExecSummaryRedesign:
    """Executive summary renders structured stat tiles and a risk badge."""

    def _generate(self, tmp_path, findings, summary="**Risk:** test"):
        from appsec_galaxy.reporting.html import generate_html_report
        out = tmp_path / 'out'
        out.mkdir()
        generate_html_report(findings, summary, str(out), '/tmp/demo', {'python'})
        return (out / 'report.html').read_text()

    def test_high_risk_badge_and_tiles(self, tmp_path):
        html_out = self._generate(tmp_path, [
            {'tool': 'semgrep', 'check_id': 'sqli', 'path': 'a.py', 'severity': 'critical',
             'start': {'line': 1}, 'extra': {'message': 'x'}, 'category': 'security'},
        ])
        assert 'risk-badge risk-high' in html_out
        assert 'exec-tiles' in html_out

    def test_low_risk_when_clean(self, tmp_path):
        html_out = self._generate(tmp_path, [])
        assert 'risk-badge risk-low' in html_out

    def test_misconfig_tile_only_when_present(self, tmp_path):
        misconf = {'tool': 'trivy', 'vulnerability_id': 'DS002', 'path': 'Dockerfile', 'line': 1,
                   'description': 'root user', 'severity': 'high',
                   'finding_type': 'misconfiguration', 'category': 'security'}
        html_with = self._generate(tmp_path, [misconf])
        assert 'IaC Misconfigs' in html_with
        html_without = self._generate_second(tmp_path, [
            {'tool': 'semgrep', 'check_id': 'x', 'path': 'a.py', 'severity': 'high',
             'start': {'line': 1}, 'extra': {'message': 'x'}, 'category': 'security'},
        ])
        assert 'IaC Misconfigs' not in html_without

    def _generate_second(self, tmp_path, findings):
        from appsec_galaxy.reporting.html import generate_html_report
        out = tmp_path / 'out2'
        out.mkdir()
        generate_html_report(findings, "**Risk:** test", str(out), '/tmp/demo', {'python'})
        return (out / 'report.html').read_text()

    def test_deps_tile_excludes_misconfigs(self, tmp_path):
        """A misconfig-only scan must show Dependencies 0, not 1."""
        misconf = {'tool': 'trivy', 'vulnerability_id': 'DS002', 'path': 'Dockerfile', 'line': 1,
                   'description': 'root user', 'severity': 'high',
                   'finding_type': 'misconfiguration', 'category': 'security'}
        html_out = self._generate(tmp_path, [misconf])
        deps_num = re.search(r'<div class="num">(\d+)</div>\s*<div class="label">Dependencies</div>', html_out)
        assert deps_num and deps_num.group(1) == '0'

    def test_kev_tile_only_when_present(self, tmp_path):
        kev = {'tool': 'trivy', 'vulnerability_id': 'CVE-1', 'path': 'pom.xml', 'line': 1,
               'description': 'd', 'severity': 'critical', 'in_kev': True, 'category': 'security'}
        html_with = self._generate(tmp_path, [kev])
        assert 'Actively Exploited' in html_with

    def test_no_kev_tile_when_absent(self, tmp_path):
        html_out = self._generate(tmp_path, [
            {'tool': 'semgrep', 'check_id': 'x', 'path': 'a.py', 'severity': 'high',
             'start': {'line': 1}, 'extra': {'message': 'x'}, 'category': 'security'},
        ])
        assert 'Actively Exploited' not in html_out

    def test_secrets_force_high_risk(self, tmp_path):
        html_out = self._generate(tmp_path, [
            {'tool': 'gitleaks', 'RuleID': 'aws-key', 'File': 'c.py', 'StartLine': 1,
             'Description': 'AWS key', 'category': 'security'},
        ])
        assert 'risk-badge risk-high' in html_out

    def test_high_tile_excludes_code_quality_errors(self, tmp_path):
        """Regression: pylint "error" findings were counted into the HIGH
        tile (4) while the summary text counted security only (1)."""
        findings = [
            {'tool': 'semgrep', 'check_id': 'x', 'path': 'a.py', 'severity': 'high',
             'start': {'line': 1}, 'extra': {'message': 'x'}, 'category': 'security'},
        ] + [
            {'tool': 'pylint', 'check_id': f'E{i}', 'path': 'b.py', 'severity': 'high',
             'start': {'line': i}, 'extra': {'message': 'bug', 'severity': 'error',
                                             'metadata': {'category': 'code_quality'}},
             'category': 'code_quality'}
            for i in range(3)
        ]
        html_out = self._generate(tmp_path, findings)
        high = re.search(r'<div class="num">(\d+)</div>\s*<div class="label">High</div>', html_out)
        assert high and high.group(1) == '1'
        cq = re.search(r'<div class="num">(\d+)</div>\s*<div class="label">Code Quality</div>', html_out)
        assert cq and cq.group(1) == '3'

    def test_badge_and_fallback_text_agree_on_risk(self, tmp_path):
        """Regression: badge said High Risk (secrets rule) while the fallback
        text said Medium Risk (critical-only rule) on the same report."""
        from appsec_galaxy.reporting.ai_summary import build_fallback_summary
        findings = [
            {'tool': 'gitleaks', 'RuleID': 'aws-key', 'File': 'c.py', 'StartLine': 1,
             'Description': 'AWS key', 'category': 'security'},
            {'tool': 'semgrep', 'check_id': 'x', 'path': 'a.py', 'severity': 'high',
             'start': {'line': 1}, 'extra': {'message': 'x'}, 'category': 'security'},
        ]
        text = build_fallback_summary(findings)
        html_out = self._generate(tmp_path, findings, summary=text)
        assert 'risk-badge risk-high' in html_out
        assert 'High Risk' in text and 'Medium Risk' not in text
        assert '1 high-severity issues' in text
        assert '1 secrets detected' in text

class TestSummaryStats:
    """compute_summary_stats / risk_assessment are the single source of truth
    for every number on the executive summary."""

    def test_counts_security_only_for_severity_buckets(self):
        from appsec_galaxy.reporting.ai_summary import compute_summary_stats
        stats = compute_summary_stats([
            {'tool': 'semgrep', 'severity': 'critical', 'category': 'security'},
            {'tool': 'semgrep', 'severity': 'HIGH', 'category': 'security'},
            {'tool': 'trivy', 'severity': 'high', 'finding_type': 'misconfiguration', 'category': 'security'},
            {'tool': 'trivy', 'severity': 'critical', 'in_kev': True, 'category': 'security'},
            {'tool': 'gitleaks', 'category': 'security'},
            {'tool': 'pylint', 'severity': 'high', 'extra': {'severity': 'error'}, 'category': 'code_quality'},
            {'tool': 'eslint', 'severity': 'critical',
             'extra': {'metadata': {'category': 'code_quality'}}},
        ])
        assert stats == {
            'total_security': 5, 'total_code_quality': 2,
            'critical': 2, 'high': 2, 'sast': 2, 'secrets': 1,
            'deps': 1, 'misconfigs': 1, 'kev': 1,
        }

    @pytest.mark.parametrize("stats, expected", [
        ({'critical': 1, 'high': 0, 'secrets': 0}, ('high', 'High Risk')),
        ({'critical': 0, 'high': 0, 'secrets': 1}, ('high', 'High Risk')),
        ({'critical': 0, 'high': 3, 'secrets': 0}, ('medium', 'Medium Risk')),
        ({'critical': 0, 'high': 0, 'secrets': 0}, ('low', 'Low Risk')),
    ])
    def test_risk_assessment(self, stats, expected):
        from appsec_galaxy.reporting.ai_summary import risk_assessment
        assert risk_assessment(stats) == expected

    def test_fallback_summary_for_no_findings(self):
        from appsec_galaxy.reporting.ai_summary import build_fallback_summary
        assert 'no critical or high-severity issues' in build_fallback_summary([])

    def test_fallback_summary_includes_context_and_code_quality_section(self):
        from appsec_galaxy.reporting.ai_summary import build_fallback_summary
        text = build_fallback_summary(
            [{'tool': 'pylint', 'severity': 'low', 'category': 'code_quality'}],
            context_summary='\n\nCONTEXT-MARKER',
        )
        assert 'Code Quality Issues (1 total)' in text
        assert 'CONTEXT-MARKER' in text
        assert 'Low Risk' in text

    def test_web_scan_response_counts_security_only(self, monkeypatch, tmp_path):
        """The web result cards read scan_summary.high_findings; they must
        match the report tiles (a pylint error is not a high security issue)."""
        if 'appsec_galaxy.web_app' in sys.modules:
            del sys.modules['appsec_galaxy.web_app']
        from appsec_galaxy import web_app
        findings = [
            {'tool': 'semgrep', 'check_id': 'x', 'path': 'a.py', 'severity': 'high',
             'start': {'line': 1}, 'extra': {'message': 'x'}, 'category': 'security'},
            {'tool': 'pylint', 'check_id': 'E1', 'path': 'b.py', 'severity': 'high',
             'start': {'line': 1}, 'extra': {'message': 'bug', 'severity': 'error',
                                             'metadata': {'category': 'code_quality'}},
             'category': 'code_quality'},
        ]
        monkeypatch.setattr(web_app, 'run_security_scans', lambda *a, **k: findings)
        monkeypatch.setattr(web_app, 'track_usage', lambda: None)
        # finalize_scan is the shared post-scan pipeline; identity here
        monkeypatch.setattr(web_app, 'finalize_scan', lambda f, *a, **k: f)
        web_app.app.config['TESTING'] = True
        resp = web_app.app.test_client().post('/scan', json={
            'repo_path': str(tmp_path), 'selected_tools': ['semgrep', 'code_quality'],
        })
        assert resp.status_code == 200, resp.get_json()
        summary = resp.get_json()['scan_summary']
        assert summary['total_findings'] == 2
        assert summary['high_findings'] == 1
        assert summary['critical_findings'] == 0

    def test_no_inline_copies_of_the_fallback_summary_remain(self):
        """The summary text used to be pasted into main.py twice and web_app.py
        once, each with its own risk formula. Only ai_summary.py may own it."""
        root = Path(__file__).resolve().parent.parent / 'src' / 'appsec_galaxy'
        owners = [p for p in root.rglob('*.py')
                  if 'high-severity issues needing prompt remediation' in p.read_text()]
        assert [p.name for p in owners] == ['ai_summary.py']

class TestSummaryTopicSections:
    """Exec summary topics render as bordered blocks (_wrap_topic_sections)."""

    def test_full_line_bold_becomes_topic_heading(self):
        from appsec_galaxy.reporting.ai_summary import _markdown_to_html
        result = _markdown_to_html("**Recommended Actions:**\n- Fix it")
        assert 'summary-topic' in result
        assert 'Recommended Actions' in result
        assert 'Recommended Actions:</h4>' not in result  # trailing colon dropped

    def test_topics_wrapped_in_bordered_blocks(self):
        from appsec_galaxy.reporting.ai_summary import _markdown_to_html
        md = "Intro line\n\n**Security Issues:**\n- one\n\n**Recommended Actions:**\n- two"
        result = _markdown_to_html(md)
        assert result.count('summary-topic-block') == 2
        assert 'summary-intro' in result

    def test_inline_bold_is_not_a_section(self):
        from appsec_galaxy.reporting.ai_summary import _markdown_to_html
        result = _markdown_to_html("**Risk Assessment:** High Risk")
        assert 'summary-topic-block' not in result
        assert '<strong>Risk Assessment:</strong>' in result

    def test_no_headings_is_noop(self):
        from appsec_galaxy.reporting.ai_summary import _markdown_to_html
        result = _markdown_to_html("Just a plain sentence.")
        assert 'summary-topic-block' not in result
