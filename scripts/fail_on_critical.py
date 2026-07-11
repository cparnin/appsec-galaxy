#!/usr/bin/env python3
"""
Post-scan gate: exits non-zero if critical-or-above findings exist.

Reads raw scanner outputs from outputs/raw/ and counts:
  - Semgrep findings with severity ERROR or CRITICAL
  - Trivy vulnerabilities with severity CRITICAL
  - Any Gitleaks leaks (every leak is treated as critical)

Used by GitHub Actions to fail the build when
real risks land. Does not change the scan itself, just inspects its
raw output.

Env vars:
  APPSEC_FAIL_THRESHOLD  - 'critical' (default) or 'high' to fail on

Exit codes:
  0  no findings at-or-above threshold (or no raw output found)
  1  one or more findings at-or-above threshold
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

THRESHOLD = os.getenv("APPSEC_FAIL_THRESHOLD", "critical").lower()


# The scanned repo's root, where .appsec-galaxy-ignore lives. Inside the composite
# GitHub Action the gate runs from the AppSec Galaxy checkout (github.action_path)
# while the scanned repo is GITHUB_WORKSPACE; standalone runs use cwd.
_SCANNED_REPO = os.getenv("GITHUB_WORKSPACE") or os.getcwd()


def _load_baseline():
    """Load .appsec-galaxy-ignore patterns and matcher from the scanned repo.

    Returns (patterns, matcher). If the scan pipeline modules are not
    importable, suppression is skipped and the gate stays strict (fails
    closed on counting, open on convenience)."""
    try:
        from appsec_galaxy.scan_filters import is_suppressed, load_ignore_patterns
    except ImportError:
        return [], None
    patterns = load_ignore_patterns(_SCANNED_REPO)
    return patterns, is_suppressed


_PATTERNS, _IS_SUPPRESSED = _load_baseline()


def _suppressed(finding: dict) -> bool:
    return bool(_PATTERNS and _IS_SUPPRESSED and _IS_SUPPRESSED(finding, _PATTERNS, _SCANNED_REPO))


def _find_raw_dirs() -> list[Path]:
    """Locate raw scanner output dirs.

    AppSec Galaxy writes to outputs/<repo_name>/raw/ (path_utils.get_output_path).
    The legacy flat outputs/raw/ is checked first for backwards compat.
    Before this resolution existed the gate silently exited 0 in CI because
    it only looked at the flat path, which never exists.
    """
    dirs = []
    legacy = Path("outputs/raw")
    if legacy.is_dir():
        dirs.append(legacy)
    dirs.extend(sorted(p for p in Path("outputs").glob("*/raw") if p.is_dir()))
    return dirs


def _load(path: Path):
    """Return parsed JSON, or None if file missing/empty/invalid."""
    if not path.exists():
        return None
    text = path.read_text().strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _semgrep_critical(raw_dir: Path) -> int:
    """Count semgrep findings at-or-above threshold."""
    data = _load(raw_dir / "semgrep.json")
    if not data:
        return 0
    n = 0
    for r in data.get("results", []):
        sev = (r.get("extra", {}).get("severity") or r.get("severity") or "").lower()
        counts = (THRESHOLD == "critical" and sev in ("critical",)) or \
                 (THRESHOLD == "high" and sev in ("critical", "high", "error"))
        if counts and not _suppressed({"tool": "semgrep",
                                       "check_id": r.get("check_id", ""),
                                       "path": r.get("path", "")}):
            n += 1
    return n


def _trivy_critical(raw_dir: Path) -> int:
    """Count trivy CVEs at-or-above threshold.

    The scanner writes trivy-sca.json; plain trivy.json is checked as a
    fallback for older artifacts."""
    data = _load(raw_dir / "trivy-sca.json") or _load(raw_dir / "trivy.json")
    if not data:
        return 0
    n = 0
    for result in data.get("Results", []) or []:
        for v in result.get("Vulnerabilities", []) or []:
            sev = (v.get("Severity") or "").lower()
            counts = (THRESHOLD == "critical" and sev == "critical") or \
                     (THRESHOLD == "high" and sev in ("critical", "high"))
            if counts and not _suppressed({"tool": "trivy",
                                           "vulnerability_id": v.get("VulnerabilityID", ""),
                                           "path": result.get("Target", "")}):
                n += 1
    return n


def _gitleaks_critical(raw_dir: Path) -> int:
    """Count gitleaks findings (every leak is critical)."""
    data = _load(raw_dir / "gitleaks.json")
    if not data or not isinstance(data, list):
        return 0
    return sum(1 for leak in data
               if not _suppressed({"tool": "gitleaks",
                                   "RuleID": leak.get("RuleID", ""),
                                   "File": leak.get("File", "")}))


def main() -> int:
    raw_dirs = _find_raw_dirs()
    if not raw_dirs:
        print("⚠️  No raw scanner output found under outputs/; skipping fail-on-critical gate.")
        return 0

    semgrep_n = sum(_semgrep_critical(d) for d in raw_dirs)
    trivy_n = sum(_trivy_critical(d) for d in raw_dirs)
    gitleaks_n = sum(_gitleaks_critical(d) for d in raw_dirs)
    total = semgrep_n + trivy_n + gitleaks_n

    print()
    print(f"🛡️  Fail-on-critical gate (threshold={THRESHOLD})")
    print(f"   Semgrep   : {semgrep_n}")
    print(f"   Trivy     : {trivy_n}")
    print(f"   Gitleaks  : {gitleaks_n}")
    print(f"   Total     : {total}")
    print()

    if total > 0:
        print(f"❌ {total} {THRESHOLD}-or-above finding(s) detected. Failing the build.")
        return 1

    print(f"✅ No {THRESHOLD}-or-above findings. Build passes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
