"""
Scan trend history: new vs fixed findings across scans.

After each scan, a compact summary (counts + finding fingerprints) is
appended to history.json in the repo's output directory. The delta vs the
previous scan ("3 new, 5 fixed") is returned for the scan summary and
report. Fingerprints are sha256 of tool|rule|path, so they are stable across
line-number drift and contain no secret material.
"""

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from appsec_galaxy.finding import finding_path, finding_rule_id, finding_severity
from appsec_galaxy.logging_config import get_logger

logger = get_logger(__name__)

HISTORY_FILENAME = "history.json"
_MAX_ENTRIES = 20


def fingerprint(finding: dict[str, Any]) -> str:
    """Stable identity for a finding: tool|rule|path (no line numbers, no secrets)."""
    key = f"{finding.get('tool', '')}|{finding_rule_id(finding)}|{finding_path(finding)}"
    return hashlib.sha256(key.encode('utf-8', errors='replace')).hexdigest()[:16]


def _load_history(history_file: Path) -> list[dict[str, Any]]:
    if not history_file.exists():
        return []
    try:
        with open(history_file) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(f"Could not read scan history (starting fresh): {e}")
        return []


def record_and_diff(findings: list[dict[str, Any]], output_dir: str | Path) -> dict[str, Any]:
    """Append this scan to history and return the delta vs the previous scan.

    Returns {'total', 'new', 'fixed', 'previous_total', 'first_scan'}.
    Never raises: on any failure returns a delta with first_scan=True.
    """
    try:
        history_file = Path(output_dir) / HISTORY_FILENAME
        history = _load_history(history_file)

        current_fps = {fingerprint(f) for f in findings}
        by_severity: dict[str, int] = {}
        for f in findings:
            sev = finding_severity(f)
            by_severity[sev] = by_severity.get(sev, 0) + 1

        previous = history[-1] if history else None
        if previous:
            prev_fps = set(previous.get('fingerprints', []))
            delta = {
                'total': len(findings),
                'new': len(current_fps - prev_fps),
                'fixed': len(prev_fps - current_fps),
                'previous_total': previous.get('total', 0),
                'first_scan': False,
            }
        else:
            delta = {'total': len(findings), 'new': len(findings), 'fixed': 0,
                     'previous_total': 0, 'first_scan': True}

        history.append({
            'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            'total': len(findings),
            'by_severity': by_severity,
            'fingerprints': sorted(current_fps),
        })
        history = history[-_MAX_ENTRIES:]

        history_file.parent.mkdir(parents=True, exist_ok=True)
        with open(history_file, 'w') as fh:
            json.dump(history, fh, indent=2)

        return delta
    except Exception as e:
        logger.warning(f"Scan history recording failed (continuing): {e}")
        return {'total': len(findings), 'new': 0, 'fixed': 0, 'previous_total': 0, 'first_scan': True}
