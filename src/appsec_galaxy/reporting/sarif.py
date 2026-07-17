"""
SARIF 2.1.0 exporter.

Converts aggregated AppSec Galaxy findings (all scanner dict shapes) into a single
SARIF log so results can flow into GitHub code scanning, VS Code SARIF
viewers, and other standard tooling. Written to outputs/report.sarif
alongside the HTML report on every scan.
"""

import hashlib
import json
from pathlib import Path
from typing import Any

from appsec_galaxy.finding import finding_line, finding_message, finding_path, finding_rule_id, finding_severity
from appsec_galaxy.logging_config import get_logger

logger = get_logger(__name__)

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# SARIF level mapping: error > warning > note
_SEVERITY_TO_LEVEL = {
    'critical': 'error',
    'high': 'error',
    'error': 'error',
    'medium': 'warning',
    'warning': 'warning',
    'low': 'note',
    'info': 'note',
}

# GitHub's Security tab ranks alerts by the rule's security-severity property
# (a string "0.0".."10.0"), not the SARIF level.
_SEVERITY_TO_SECURITY_SEVERITY = {
    'critical': '9.5',
    'high': '8.0',
    'error': '8.0',
    'medium': '5.5',
    'warning': '5.5',
    'low': '3.0',
    'info': '3.0',
}


def _relative_uri(path: str, repo_path: str) -> str:
    """SARIF artifact URIs should be repo-relative with forward slashes."""
    if not path:
        return "unknown"
    p = path.replace('\\', '/')
    repo = str(repo_path).replace('\\', '/').rstrip('/')
    if repo and p.startswith(repo + '/'):
        p = p[len(repo) + 1:]
    return p.lstrip('/') or "unknown"


def _help_uri(f: dict[str, Any]) -> str | None:
    """Best-available reference URL from the source tool, if any."""
    meta = (f.get('extra') or {}).get('metadata') or {}
    if isinstance(meta, dict):
        for key in ('source', 'shortlink'):
            uri = meta.get(key)
            if isinstance(uri, str) and uri.startswith('http'):
                return uri
    refs = f.get('references')
    if isinstance(refs, list) and refs and isinstance(refs[0], str) and refs[0].startswith('http'):
        return refs[0]
    return None


def _fingerprint(rule_id: str, uri: str, f: dict[str, Any]) -> str:
    """Stable per-finding hash so GitHub dedups alerts across runs and tracks
    fix/reopen lifecycle. Prefers the matched snippet (survives the finding
    moving lines); falls back to the line number."""
    snippet = ''
    extra = f.get('extra') or {}
    if isinstance(extra, dict):
        snippet = str(extra.get('lines') or '').strip()
    basis = f"{rule_id}:{uri}:{snippet or finding_line(f)}"
    return hashlib.sha256(basis.encode('utf-8', 'replace')).hexdigest()


def findings_to_sarif(findings: list[dict[str, Any]], repo_path: str = "") -> dict[str, Any]:
    """Build a SARIF log dict from emitted finding dicts (any scanner shape)."""
    rules: dict[str, dict[str, Any]] = {}
    results = []

    for f in findings:
        rule_id = finding_rule_id(f)
        tool = f.get('tool', 'appsec-galaxy')
        severity = finding_severity(f)
        message = finding_message(f)

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": message[:200] or rule_id},
                "properties": {
                    "tool": tool,
                    "category": f.get('category', 'security'),
                    "security-severity": _SEVERITY_TO_SECURITY_SEVERITY.get(severity, '5.5'),
                },
            }
            help_uri = _help_uri(f)
            if help_uri:
                rules[rule_id]["helpUri"] = help_uri

        uri = _relative_uri(finding_path(f), repo_path)
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SEVERITY_TO_LEVEL.get(severity, 'warning'),
            "message": {"text": message or rule_id},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": max(1, finding_line(f))},
                }
            }],
            "partialFingerprints": {
                "appsecGalaxy/v1": _fingerprint(rule_id, uri, f),
            },
            "properties": {"tool": tool, "severity": severity},
        }
        # Carry exploit intel and reachability through when present
        for key in ('epss_score', 'in_kev', 'exploit_priority',
                    'reachability', 'risk_priority'):
            if key in f:
                result["properties"][key] = f[key]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AppSec Galaxy",
                    "informationUri": "https://github.com/cparnin/appsec-galaxy",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def generate_sarif_report(findings: list[dict[str, Any]], output_dir: str | Path,
                          repo_path: str = "") -> Path | None:
    """Write outputs/report.sarif. Returns the path, or None on failure
    (SARIF export must never break a scan)."""
    try:
        sarif = findings_to_sarif(findings, repo_path)
        out = Path(output_dir) / "report.sarif"
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, 'w') as fh:
            json.dump(sarif, fh, indent=2)
        logger.info(f"SARIF report written to {out} ({len(findings)} results)")
        return out
    except Exception as e:
        logger.error(f"SARIF export failed: {e}")
        return None
