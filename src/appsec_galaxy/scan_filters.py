"""
Post-scan finding filters: baseline suppression and PR-diff scoping.

Baseline suppression (.appsec-galaxy-ignore):
    A `.appsec-galaxy-ignore` file in the scanned repo's root suppresses known,
    accepted findings so they stop re-alerting. One pattern per line:

        tool:rule:path-glob

    Each component supports fnmatch wildcards. Examples:
        gitleaks:generic-api-key:tests/fixtures/*
        semgrep:*sql-injection*:legacy/*
        trivy:CVE-2024-1234:*
        *:*:vendor/*
    Lines starting with # are comments.

Diff-only mode (APPSEC_DIFF_ONLY=true):
    Keeps only findings in files changed vs the base branch
    (APPSEC_DIFF_BASE, default origin/main; falls back to origin/master).
    Designed for fast PR feedback; run full scans on the main branch.

Both filters fail open: on any error the original findings are returned
unchanged so a broken ignore file or missing git ref can't hide results.
"""

import fnmatch
import os
import subprocess
from pathlib import Path
from typing import Any

from appsec_galaxy.finding import finding_path, finding_rule_id
from appsec_galaxy.logging_config import get_logger

logger = get_logger(__name__)

IGNORE_FILENAME = ".appsec-galaxy-ignore"


def load_ignore_patterns(repo_path: str) -> list[tuple[str, str, str]]:
    """Parse .appsec-galaxy-ignore into (tool, rule, path_glob) tuples."""
    ignore_file = Path(repo_path) / IGNORE_FILENAME
    if not ignore_file.exists():
        return []
    patterns = []
    try:
        for raw_line in ignore_file.read_text(encoding='utf-8', errors='replace').splitlines():
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(':', 2)
            if len(parts) != 3:
                logger.warning(f"{IGNORE_FILENAME}: skipping malformed line: {line!r} (expected tool:rule:path-glob)")
                continue
            patterns.append((parts[0].strip() or '*', parts[1].strip() or '*', parts[2].strip() or '*'))
    except OSError as e:
        logger.warning(f"Could not read {IGNORE_FILENAME}: {e}")
        return []
    return patterns


def _normalize_path(path: str, repo_path: str) -> str:
    p = (path or '').replace('\\', '/')
    repo = str(repo_path).replace('\\', '/').rstrip('/')
    if repo and p.startswith(repo + '/'):
        p = p[len(repo) + 1:]
    return p.lstrip('/')


def is_suppressed(finding: dict[str, Any], patterns: list[tuple[str, str, str]],
                  repo_path: str = '') -> bool:
    """True if the finding matches any .appsec-galaxy-ignore pattern.

    Public so the CI gate (scripts/fail_on_critical.py) applies the same
    baseline as the scan pipeline."""
    tool = str(finding.get('tool', ''))
    rule = str(finding_rule_id(finding))
    path = _normalize_path(finding_path(finding), repo_path)
    return any(
        fnmatch.fnmatch(tool, tool_pat)
        and fnmatch.fnmatch(rule, rule_pat)
        and fnmatch.fnmatch(path, path_pat)
        for tool_pat, rule_pat, path_pat in patterns
    )


def filter_suppressed(findings: list[dict[str, Any]], repo_path: str) -> tuple[list[dict[str, Any]], int]:
    """Drop findings matching .appsec-galaxy-ignore patterns. Returns (kept, suppressed_count)."""
    patterns = load_ignore_patterns(repo_path)
    if not patterns:
        return findings, 0
    kept = []
    suppressed = 0
    for f in findings:
        if is_suppressed(f, patterns, repo_path):
            suppressed += 1
        else:
            kept.append(f)
    if suppressed:
        logger.info(f"{IGNORE_FILENAME}: suppressed {suppressed} baseline finding(s)")
    return kept, suppressed


def get_changed_files(repo_path: str, base_ref: str | None = None) -> set[str] | None:
    """Repo-relative paths changed vs the merge-base with base_ref.

    Includes uncommitted changes. Returns None if the diff cannot be
    computed (not a git repo, missing base ref), so callers fail open.
    """
    candidates: list[str | None] = [base_ref] if base_ref else []
    candidates += [os.getenv('APPSEC_DIFF_BASE', '').strip() or None, 'origin/main', 'origin/master']
    tried = []
    for ref in candidates:
        if not ref or ref in tried:
            continue
        tried.append(ref)
        try:
            result = subprocess.run(
                ['git', 'diff', '--name-only', f'{ref}...HEAD'],
                cwd=repo_path, capture_output=True, text=True, timeout=30, shell=False,
            )
            if result.returncode != 0:
                continue
            changed = {line.strip() for line in result.stdout.splitlines() if line.strip()}
            # Also include uncommitted working-tree changes
            wt = subprocess.run(
                ['git', 'diff', '--name-only', 'HEAD'],
                cwd=repo_path, capture_output=True, text=True, timeout=30, shell=False,
            )
            if wt.returncode == 0:
                changed |= {line.strip() for line in wt.stdout.splitlines() if line.strip()}
            logger.info(f"Diff-only scope: {len(changed)} changed file(s) vs {ref}")
            return changed
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
            logger.warning(f"Diff-only: git diff vs {ref} failed: {e}")
            continue
    logger.warning("Diff-only requested but no usable base ref; scanning everything (fail open)")
    return None


def filter_diff_only(findings: list[dict[str, Any]], repo_path: str) -> tuple[list[dict[str, Any]], int]:
    """When APPSEC_DIFF_ONLY=true, keep only findings in changed files.

    Trivy findings follow the same rule via their manifest path (Target), so
    dependency findings survive only when the manifest itself changed.
    Returns (kept, filtered_count).
    """
    if os.getenv('APPSEC_DIFF_ONLY', 'false').lower() != 'true':
        return findings, 0
    changed = get_changed_files(repo_path)
    if changed is None:
        return findings, 0
    kept = [f for f in findings if _normalize_path(finding_path(f), repo_path) in changed]
    filtered = len(findings) - len(kept)
    if filtered:
        logger.info(f"Diff-only: filtered {filtered} finding(s) outside the changed-file set")
    return kept, filtered
