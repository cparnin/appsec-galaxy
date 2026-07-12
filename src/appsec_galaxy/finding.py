"""
Canonical Finding model.

Every scanner historically emitted its own dict shape (semgrep passes raw
results through, gitleaks uses capitalized keys, trivy builds a custom dict).
Finding gives them one typed boundary: each scanner constructs a Finding via
its from_* constructor, then emits finding.to_dict().

to_dict() is byte-compatible with the dict shapes the pipeline consumed
before this class existed, so downstream code (reporting, cross-file
analysis, remediation, MCP) is unaffected. New code should prefer the typed
attributes (tool, severity, path, line, message) over digging into payload.
"""

from dataclasses import dataclass, field
from typing import Any


def finding_path(d: dict[str, Any]) -> str:
    """File path from any emitted finding dict shape (semgrep/gitleaks/trivy/linters)."""
    return d.get('path') or d.get('File') or ''


def finding_line(d: dict[str, Any]) -> int:
    """Start line from any emitted finding dict shape."""
    line = d.get('line') or d.get('StartLine') or (d.get('start') or {}).get('line')
    return int(line) if line else 1


def finding_rule_id(d: dict[str, Any]) -> str:
    """Stable rule/vuln identifier from any emitted finding dict shape."""
    return (d.get('check_id') or d.get('vulnerability_id')
            or d.get('RuleID') or d.get('rule_id') or 'unknown')


def finding_message(d: dict[str, Any]) -> str:
    """Human-readable message from any emitted finding dict shape."""
    return ((d.get('extra') or {}).get('message') or d.get('description')
            or d.get('Description') or d.get('message') or finding_rule_id(d))


def finding_severity(d: dict[str, Any]) -> str:
    """Normalized severity; secrets (gitleaks) default to critical."""
    sev = str(d.get('severity', '')).lower()
    if not sev and d.get('tool') == 'gitleaks':
        return 'critical'
    return sev or 'medium'


@dataclass
class Finding:
    """One normalized security or code-quality finding."""

    tool: str                       # 'semgrep' | 'gitleaks' | 'trivy' | ...
    category: str                   # 'security' | 'code_quality'
    severity: str | None = None     # 'critical' | 'high' | 'medium' | 'low'
    path: str | None = None         # file path relative to scanned repo
    line: int | None = None
    message: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Backwards-compatible dict for the existing pipeline."""
        return dict(self.payload)

    @classmethod
    def from_semgrep(cls, raw: dict[str, Any], normalized_severity: str, category: str) -> "Finding":
        """Wrap a raw semgrep result. Payload preserves the raw semgrep shape
        with severity/tool/category set, exactly as the scanner emitted before."""
        return cls(
            tool="semgrep",
            category=category,
            severity=normalized_severity,
            path=raw.get("path"),
            line=(raw.get("start") or {}).get("line"),
            message=(raw.get("extra") or {}).get("message"),
            payload={**raw, "severity": normalized_severity, "tool": "semgrep", "category": category},
        )

    @classmethod
    def from_gitleaks(cls, raw: dict[str, Any]) -> "Finding":
        """Wrap a raw gitleaks result (capitalized keys preserved in payload).
        Secrets have no scanner-assigned severity; the pipeline treats them
        as their own class of finding."""
        return cls(
            tool="gitleaks",
            category="security",
            severity=None,
            path=raw.get("File"),
            line=raw.get("StartLine"),
            message=raw.get("Description"),
            payload={**raw, "tool": "gitleaks", "category": "security"},
        )

    @classmethod
    def from_trivy(cls, vuln: dict[str, Any], target: str) -> "Finding":
        """Build the standardized trivy dependency finding."""
        severity = vuln.get("Severity", "UNKNOWN").lower()
        description = (
            f"{vuln.get('PkgName', 'Unknown')} {vuln.get('InstalledVersion', '')}: "
            f"{vuln.get('Title', vuln.get('VulnerabilityID', 'Unknown vulnerability'))}"
        )
        payload = {
            "path": target,
            "line": 1,  # Dependencies don't have specific lines
            "description": description,
            "severity": severity,
            "vulnerability_id": vuln.get("VulnerabilityID", ""),
            "pkg_name": vuln.get("PkgName", ""),
            "installed_version": vuln.get("InstalledVersion", ""),
            "fixed_version": vuln.get("FixedVersion", ""),
            "references": vuln.get("References", []),
            "tool": "trivy",
            "category": "security",
        }
        return cls(
            tool="trivy",
            category="security",
            severity=severity,
            path=target,
            line=1,
            message=description,
            payload=payload,
        )
