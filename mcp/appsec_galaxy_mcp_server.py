#!/usr/bin/env python3
"""
AppSec Galaxy MCP Server (FastMCP).

Exposes AppSec Galaxy security scanning to MCP clients.
Built on the official `mcp` SDK: tool schemas are generated from the typed
function signatures below and arguments are validated at the RPC boundary,
replacing the previous hand-rolled JSON-RPC implementation.

All 16 tool names and their output formats are unchanged from the previous
server, so existing client conversations and integrations keep working.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from typing import Any

from mcp.server.fastmcp import FastMCP

# Add AppSec Galaxy src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

SERVER_NAME = "appsec-galaxy"
mcp_app = FastMCP(SERVER_NAME)
mcp = mcp_app

# Shell metacharacters rejected in repo_path before any discovery/subprocess
# use. Defense in depth: subprocess calls use shell=False everywhere, but a
# hostile repo_path should die at the boundary, not deep in a tool.
_DANGEROUS_CHARS = (';', '|', '&', '$', '`', '\x00', '\n', '\r')

# Code-quality linter outputs share one normalized shape (produced by the
# AppSec Galaxy code_quality scanner). Default severity differs only for phpstan.
_CODE_QUALITY_LINTERS = {
    'eslint': ('javascript/typescript', 'medium'),
    'pylint': ('python', 'medium'),
    'checkstyle': ('java', 'medium'),
    'golangci-lint': ('go', 'medium'),
    'rubocop': ('ruby', 'medium'),
    'clippy': ('rust', 'medium'),
    'phpstan': ('php', 'high'),
}


def _validate_repo_arg(repo_path: str) -> str:
    """Boundary validation for the repo_path argument of every tool."""
    if not repo_path or not isinstance(repo_path, str):
        raise ValueError("repo_path must be a non-empty string")
    if len(repo_path) > 4096:
        raise ValueError("repo_path too long")
    if any(c in repo_path for c in _DANGEROUS_CHARS):
        raise ValueError("repo_path contains disallowed characters")
    # No parent-directory traversal: an MCP client (or a prompt-injected LLM
    # driving one) must not walk out of the allowed scan roots.
    if ".." in repo_path.replace("\\", "/").split("/"):
        raise ValueError("repo_path must not contain '..' path segments")
    return repo_path


class AppSecGalaxyMCPCore:
    """AppSec Galaxy installation discovery, repo lookup, and scan orchestration."""

    def __init__(self):
        self.appsec_galaxy_path = self._find_appsec_galaxy_installation()
        # Background scan tracking: canonical repo_path -> threading.Thread
        self._active_scans = {}
        self._active_scans_lock = threading.Lock()
        # Path utilities for repo/branch-aware output structure
        try:
            from appsec_galaxy.config import BASE_OUTPUT_DIR
            from appsec_galaxy.path_utils import get_output_path
            self.get_output_path = get_output_path
            self.base_output_dir = BASE_OUTPUT_DIR
        except ImportError:
            self.get_output_path = None
            self.base_output_dir = None

    # ----- setup helpers -----

    def _find_appsec_galaxy_installation(self):
        """Find AppSec Galaxy installation directory. Honors APPSEC_GALAXY_PATH env var."""
        def is_install(path):
            return os.path.isfile(
                os.path.join(path, "src", "appsec_galaxy", "main.py")
            )

        env_path = os.environ.get("APPSEC_GALAXY_PATH")
        if env_path and is_install(env_path):
            return os.path.abspath(env_path)

        common_locations = [
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),  # Parent of mcp directory
            os.path.expanduser("~/repos/personal/appsec-galaxy"),
            os.path.expanduser("~/appsec-galaxy"),
            "./appsec-galaxy",
            "../appsec-galaxy",
        ]
        for location in common_locations:
            if is_install(location):
                return os.path.abspath(location)

        searched_paths = "\n".join([f"  - {loc}" for loc in common_locations])
        raise RuntimeError(f"""AppSec Galaxy installation not found.

Searched locations:
{searched_paths}

Please either:
1. Set APPSEC_GALAXY_PATH environment variable to your AppSec Galaxy installation path
2. Install AppSec Galaxy in one of the searched locations
3. Run the server from the AppSec Galaxy checkout

Example: export APPSEC_GALAXY_PATH="/path/to/appsec-galaxy" """)

    def _find_repo_search_paths(self):
        """Get repository search paths from environment or defaults.

        These double as the allowlist of roots a scan target may live under
        (see _assert_allowed): the server only scans what it would discover.
        Set APPSEC_MCP_ALLOWED_ROOTS (colon-separated) to lock this down
        further than the defaults.
        """
        base_paths = []
        if os.environ.get("APPSEC_MCP_ALLOWED_ROOTS"):
            base_paths.extend(os.environ["APPSEC_MCP_ALLOWED_ROOTS"].split(":"))
            return base_paths  # explicit allowlist replaces the broad defaults
        if "REPO_SEARCH_PATHS" in os.environ:
            base_paths.extend(os.environ["REPO_SEARCH_PATHS"].split(":"))
        user_home = os.path.expanduser("~")
        base_paths.extend([
            os.path.join(user_home, "repos"),
            os.path.join(user_home, "projects"),
            user_home,
            "."
        ])
        return base_paths

    def _assert_allowed(self, resolved_path):
        """Confine a resolved scan target to the allowed roots. Blocks a
        client from pointing the scanner at arbitrary local directories
        (source disclosure via the findings/snippet tools)."""
        from appsec_galaxy.scanners.validation import path_within_roots
        if not path_within_roots(resolved_path, self._find_repo_search_paths()):
            raise ValueError(
                "Repository is outside the allowed scan roots. Set "
                "APPSEC_MCP_ALLOWED_ROOTS to permit this location."
            )
        return resolved_path

    def find_repo(self, repo_path):
        """Smart repo discovery with fuzzy matching. Input is validated at the
        tool boundary (see _validate_repo_arg) before reaching here; the
        resolved target is then confined to the allowed roots."""
        if os.path.exists(repo_path):
            return self._assert_allowed(os.path.abspath(repo_path))

        search_paths = self._find_repo_search_paths()
        for base_path in search_paths:
            candidate = os.path.join(base_path, repo_path)
            if os.path.exists(candidate):
                return self._assert_allowed(os.path.abspath(candidate))

        # Fuzzy matching (nodejsgoof -> nodejs-goof)
        for search_dir in search_paths:
            if os.path.isdir(search_dir):
                try:
                    for item in os.listdir(search_dir):
                        if repo_path.lower() in item.lower() or item.lower() in repo_path.lower():
                            full_path = os.path.join(search_dir, item)
                            if os.path.isdir(full_path):
                                return self._assert_allowed(os.path.abspath(full_path))
                except PermissionError:
                    continue

        raise ValueError(f"Repository '{repo_path}' not found in common locations")

    def _find_python_executable(self):
        """Find appropriate Python executable."""
        venv_python = os.path.join(self.appsec_galaxy_path, ".venv", "bin", "python")
        if os.path.exists(venv_python):
            return venv_python
        for python_cmd in ["python3", "python"]:
            try:
                result = subprocess.run([python_cmd, "--version"], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return python_cmd
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return "python3"

    def _get_repo_output_path(self, repo_path):
        """Get the output path for a specific repository."""
        if self.get_output_path:
            return str(self.get_output_path(repo_path, self.base_output_dir))
        return os.path.join(self.appsec_galaxy_path, "outputs")

    def _build_scan_env(self):
        """Environment for scan/remediate subprocesses with scanner binaries on PATH."""
        env = os.environ.copy()
        env["GITHUB_ACTIONS"] = "true"  # Non-interactive
        common_bin_paths = [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/snap/bin",
            os.path.expanduser("~/.local/bin"),
            "C:\\Program Files\\gitleaks",
            "C:\\Program Files\\trivy",
        ]
        current_path = env.get("PATH", "")
        for bin_path in common_bin_paths:
            if os.path.exists(bin_path) and bin_path not in current_path:
                env["PATH"] = f"{bin_path}{os.pathsep}{current_path}"
                current_path = env["PATH"]
        return env

    # ----- background scan management -----

    def is_scan_running(self, repo_path):
        with self._active_scans_lock:
            t = self._active_scans.get(repo_path)
            return t is not None and t.is_alive()

    def _run_scan_background(self, repo_path, cmd, env, scan_timeout):
        print(f"🔄 Background scan started for {repo_path}...", file=sys.stderr)
        try:
            subprocess.run(cmd, cwd=repo_path, capture_output=True, text=True,
                           timeout=scan_timeout, env=env)
            print(f"✅ Background scan completed for {repo_path}", file=sys.stderr)
        except subprocess.TimeoutExpired:
            print(f"⏰ Background scan timed out for {repo_path}", file=sys.stderr)
        except Exception as e:
            print(f"❌ Background scan failed for {repo_path}: {e}", file=sys.stderr)
        finally:
            with self._active_scans_lock:
                self._active_scans.pop(repo_path, None)

    def start_scan(self, repo_path):
        """Kick off an AppSec Galaxy scan in the background and return immediately."""
        repo_name = os.path.basename(repo_path)
        if self.is_scan_running(repo_path):
            return json.dumps({
                "status": "scanning",
                "message": f"Scan already in progress for {repo_name}. Use get_scan_findings to poll for results."
            })

        cmd = [self._find_python_executable(), "-m", "appsec_galaxy.main"]
        env = self._build_scan_env()
        if "APPSEC_CODE_QUALITY" not in env:
            env["APPSEC_CODE_QUALITY"] = "true"
        scan_timeout = int(os.getenv('MCP_SCAN_TIMEOUT', '300'))

        t = threading.Thread(
            target=self._run_scan_background,
            args=(repo_path, cmd, env, scan_timeout),
            daemon=True,
        )
        with self._active_scans_lock:
            self._active_scans[repo_path] = t
        t.start()

        return json.dumps({
            "status": "scanning",
            "message": f"Scan started for {repo_name}. Use get_scan_findings to poll for results."
        })

    # ----- output file parsing -----

    def _load_json(self, path):
        """Load a scanner output JSON file, or None if missing/corrupt."""
        if not os.path.exists(path):
            return None
        try:
            with open(path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            print(f"Failed to parse {os.path.basename(path)}: {e}", file=sys.stderr)
            return None

    def raw_dir(self, repo_path):
        return os.path.join(self._get_repo_output_path(repo_path), "raw")


_core_instance = None
_core_lock = threading.Lock()


def _core() -> AppSecGalaxyMCPCore:
    """Singleton core, created lazily so importing this module has no side effects."""
    global _core_instance
    with _core_lock:
        if _core_instance is None:
            _core_instance = AppSecGalaxyMCPCore()
        return _core_instance


def _resolve(repo_path: str) -> str:
    """Validate then discover the repository path."""
    return _core().find_repo(_validate_repo_arg(repo_path))


def _paginate(findings: list, page: int, page_size: int) -> tuple[list, int, int, int, int]:
    """Clamp pagination params and slice. Returns (page_items, page, page_size, total, total_pages)."""
    page = max(1, min(page, 1000))
    page_size = max(1, min(page_size, 50))
    total = len(findings)
    total_pages = (total + page_size - 1) // page_size if total > 0 else 1
    start = (page - 1) * page_size
    return findings[start:start + page_size], page, page_size, total, total_pages


def _timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------
# Finding normalization (shared by get_scan_findings and per-tool endpoints)
# ---------------------------------------------------------------------------

# Aligned with src/scanners/semgrep.py: CRITICAL=critical, ERROR=high,
# WARNING=medium, INFO=low. The old server inflated these one level
# (ERROR=critical), so MCP clients saw harsher severities than reports.
_SEMGREP_SEVERITY_MAP = {
    'CRITICAL': 'critical',
    'ERROR': 'high', 'HIGH': 'high',
    'WARNING': 'medium', 'MEDIUM': 'medium',
    'INFO': 'low', 'LOW': 'low',
}
_TRIVY_SEVERITY_MAP = {'CRITICAL': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low'}


def _normalize_semgrep(data: dict, idx: int) -> dict:
    severity = _SEMGREP_SEVERITY_MAP.get(data.get('extra', {}).get('severity', 'UNKNOWN'), 'medium')
    metadata = data.get('extra', {}).get('metadata', {})
    return {
        "id": f"semgrep-{idx}",
        "tool": "semgrep",
        "category": metadata.get('category', 'security'),
        "severity": severity,
        "title": data.get('check_id', 'Unknown'),
        "description": data.get('extra', {}).get('message', ''),
        "file_path": data.get('path', ''),
        "line_start": data.get('start', {}).get('line', 0),
        "line_end": data.get('end', {}).get('line', 0),
        "code_snippet": data.get('extra', {}).get('lines', ''),
        "cwe": metadata.get('cwe', []),
        "owasp": metadata.get('owasp', []),
        "fix_available": True,
        "remediation": metadata.get('fix', 'Review and fix the vulnerability')
    }


def _normalize_gitleaks(data: dict, idx: int) -> dict:
    finding = {
        "id": f"gitleaks-{idx}",
        "tool": "gitleaks",
        "category": "security",
        "severity": "critical",  # All secrets are critical
        "title": data.get('Description', 'Secret Detected'),
        "description": f"Secret found: {data.get('RuleID', 'Unknown rule')}",
        "file_path": data.get('File', ''),
        "line_start": data.get('StartLine', 0),
        "line_end": data.get('EndLine', 0),
        "cwe": ["CWE-798"],
        "owasp": ["A02:2021 - Cryptographic Failures"],
        "fix_available": False,  # Secrets need manual review
        "remediation": "Remove secret and rotate credentials immediately"
    }
    try:
        from appsec_galaxy.scanners.gitleaks import classify_secret_confidence
        confidence, reason = classify_secret_confidence(data.get('Secret', ''))
        finding['confidence'] = confidence
        finding['confidence_reason'] = reason
    except Exception:
        pass  # confidence is best-effort; never break the MCP surface
    return finding


def _normalize_trivy(vuln: dict, idx: int, target: str = "package.json") -> dict:
    severity = _TRIVY_SEVERITY_MAP.get(vuln.get('Severity', 'UNKNOWN'), 'medium')
    fixed = vuln.get('FixedVersion')
    return {
        "id": f"trivy-{idx}",
        "tool": "trivy",
        "category": "security",
        "severity": severity,
        "vulnerability_id": vuln.get('VulnerabilityID', 'Unknown'),
        "package_name": vuln.get('PkgName', 'Unknown'),
        "installed_version": vuln.get('InstalledVersion', 'Unknown'),
        "fixed_version": fixed,
        "title": f"{vuln.get('VulnerabilityID', 'Unknown')}: {vuln.get('PkgName', 'Unknown package')}",
        "description": vuln.get('Title', '') or vuln.get('Description', ''),
        "file_path": target,
        "cwe": vuln.get('CweIDs', []) or [],
        "cvss": vuln.get('CVSS', {}),
        "references": vuln.get('References', []),
        "fix_available": bool(fixed),
        "remediation": f"Update {vuln.get('PkgName', 'package')} to version {fixed}" if fixed else "No fix available yet"
    }


def _normalize_trivy_misconfig(misconf: dict, idx: int, target: str) -> dict:
    severity = _TRIVY_SEVERITY_MAP.get(misconf.get('Severity', 'UNKNOWN'), 'medium')
    cause = misconf.get('CauseMetadata') or {}
    resolution = misconf.get('Resolution', '')
    return {
        "id": f"trivy-misconfig-{idx}",
        "tool": "trivy",
        "category": "security",
        "finding_type": "misconfiguration",
        "severity": severity,
        "vulnerability_id": misconf.get('ID', 'Unknown'),
        "title": f"{misconf.get('ID', 'Unknown')}: {misconf.get('Title', 'Misconfiguration')}",
        "description": misconf.get('Description', ''),
        "file_path": target,
        "line_start": cause.get('StartLine', 0),
        "line_end": cause.get('EndLine', 0),
        "references": misconf.get('References', []) or [],
        "fix_available": bool(resolution),
        "remediation": resolution or "Review configuration"
    }


def _iter_trivy_findings(trivy_data: dict) -> list[dict]:
    """Normalize every Trivy result: dependency CVEs (Vulnerabilities) and
    IaC/config issues (Misconfigurations) share the raw trivy-sca.json."""
    findings: list[dict] = []
    for result in trivy_data.get('Results', []):
        target = result.get('Target', 'package.json')
        for vuln in result.get('Vulnerabilities', []):
            findings.append(_normalize_trivy(vuln, len(findings), target))
        for misconf in result.get('Misconfigurations', []):
            findings.append(_normalize_trivy_misconfig(misconf, len(findings), target))
    return findings


def _normalize_eslint(file_path: str, msg: dict, idx: int) -> dict:
    severity = 'high' if msg.get('severity', 1) == 2 else 'medium'
    return {
        "id": f"eslint-{idx}",
        "tool": "eslint",
        "linter": "eslint",
        "language": "javascript/typescript",
        "category": "code_quality",
        "severity": severity,
        "rule_id": msg.get('ruleId', 'ESLint Rule'),
        "title": msg.get('ruleId', 'ESLint Rule'),
        "description": msg.get('message', ''),
        "file_path": file_path,
        "line_start": msg.get('line', 0),
        "line_end": msg.get('endLine', msg.get('line', 0)),
        "column": msg.get('column', 0),
        "fix_available": bool(msg.get('fix')),
        "remediation": f"Auto-fix available for {msg.get('ruleId')}" if msg.get('fix') else "Manual fix required"
    }


def _normalize_linter(linter: str, language: str, default_severity: str, data: dict, idx: int) -> dict:
    """Generic normalizer for linters emitting the AppSec Galaxy code-quality shape."""
    return {
        "id": f"{linter}-{idx}",
        "tool": linter,
        "linter": linter,
        "language": language,
        "category": "code_quality",
        "severity": data.get('severity', default_severity),
        "rule_id": data.get('check_id', f'{linter} rule'),
        "title": data.get('check_id', f'{linter} rule'),
        "description": data.get('extra', {}).get('message', ''),
        "file_path": data.get('path', ''),
        "line_start": data.get('start', {}).get('line', 0),
        "line_end": data.get('end', {}).get('line', 0),
        "fix_available": False,
        "remediation": f"Review {language} code quality issue and apply best practices"
    }


def _collect_code_quality_findings(core: AppSecGalaxyMCPCore, repo_path: str, linter_filter: str | None = None) -> list[dict]:
    """Parse all code-quality linter outputs into the normalized shape."""
    raw_dir = core.raw_dir(repo_path)
    findings = []
    for linter, (language, default_severity) in _CODE_QUALITY_LINTERS.items():
        if linter_filter and linter_filter != linter:
            continue
        data = core._load_json(os.path.join(raw_dir, f"{linter}.json"))
        if not isinstance(data, list):
            continue
        if linter == 'eslint':
            idx = 0
            for file_result in data:
                fp = file_result.get('filePath', '')
                for msg in file_result.get('messages', []):
                    findings.append(_normalize_eslint(fp, msg, idx))
                    idx += 1
        else:
            for idx, item in enumerate(data):
                findings.append(_normalize_linter(linter, language, default_severity, item, idx))
    return findings


def _scan_in_progress_response() -> str:
    return json.dumps({"status": "scan_in_progress", "message": "Scan is still running. Retry in a few seconds."})


# ---------------------------------------------------------------------------
# MCP tools (names and output formats unchanged from the previous server)
# ---------------------------------------------------------------------------

@mcp_app.tool()
def scan_repository(repo_path: str) -> str:
    """Run a full AppSec Galaxy security scan (Semgrep SAST, Gitleaks secrets, Trivy
    dependencies, code quality linters, cross-file analysis). Starts in the
    background; poll with get_scan_findings for results.
    repo_path accepts a name (e.g. 'nodejs-goof') or full path."""
    resolved = _resolve(repo_path)
    return _core().start_scan(resolved)


@mcp_app.tool()
def auto_remediate(repo_path: str) -> str:
    """AI-powered auto-remediation that generates fixes and creates GitHub PRs.
    Creates 2 separate PRs: one for SAST/code fixes, one for dependency updates.
    Requires prior scan."""
    core = _core()
    resolved = _resolve(repo_path)

    cmd = [core._find_python_executable(), "-m", "appsec_galaxy.main"]
    env = core._build_scan_env()
    env["APPSEC_AUTO_FIX"] = "true"
    env["APPSEC_AUTO_FIX_MODE"] = "3"  # Both SAST and dependencies
    remediate_timeout = int(os.getenv('MCP_REMEDIATE_TIMEOUT', '600'))

    print(f"🤖 Auto-remediating {resolved}...", file=sys.stderr)
    try:
        result = subprocess.run(cmd, cwd=resolved, capture_output=True, text=True,
                                timeout=remediate_timeout, env=env)
        output = result.stdout

        pr_urls = [line.split(": ")[-1] for line in output.split('\n') if "Pull Request created:" in line]
        if pr_urls:
            pr_list = '\n'.join([f"• {url}" for url in pr_urls])
            return f"""# 🚀 Auto-Remediation Complete!

**Repository**: `{os.path.basename(resolved)}`

## ✅ Pull Requests Created:
{pr_list}

## 📋 What Was Fixed:
• **PR 1**: SAST vulnerabilities and secrets (flagged for review)
• **PR 2**: Dependency updates with CVE patches

## 💡 Next Steps:
1. **Review PRs** - Check the AI-generated fixes for accuracy
2. **Run Tests** - Ensure fixes don't break functionality
3. **Merge PRs** - Deploy fixes to production
4. **Re-scan** - Verify vulnerabilities are resolved

**Mode**: Mode 3 (Comprehensive) - Separate PRs for safety
**Status**: ✅ Remediation completed successfully
"""

        failure_reason = "Unknown"
        if "No remediable findings" in output:
            failure_reason = "No auto-fixable vulnerabilities found"
        elif "OPENAI_API_KEY" in output or "ANTHROPIC_API_KEY" in output:
            failure_reason = "AI provider API key missing - check the server environment"
        elif "GitHub" in output and "token" in output:
            failure_reason = "GitHub token issue - check GITHUB_TOKEN in mcp_env"

        outputs_path = core._get_repo_output_path(resolved)
        return f"""# 🤖 Auto-Remediation Status

**Repository**: `{os.path.basename(resolved)}`
**Result**: No PRs created

## 🔍 Possible Reasons:
• **No auto-fixable vulnerabilities** - Some issues require manual fixes
• **Already fixed** - Vulnerabilities may be resolved
• **Configuration issue** - Check AI provider/GitHub credentials in the server environment

**Detected Issue**: {failure_reason}

## 💡 Troubleshooting:
1. Run "Show me the detailed report" to see all findings
2. Check `{os.path.join(outputs_path, 'pr-findings.txt')}` for details
3. Verify the AI provider key (OPENAI_API_KEY or ANTHROPIC_API_KEY) and GITHUB_TOKEN in the server environment

**Status**: ⚠️ No changes made
"""
    except subprocess.TimeoutExpired:
        timeout_msg = f"❌ Auto-remediation timed out after {remediate_timeout} seconds (increase with MCP_REMEDIATE_TIMEOUT env var)"
        if os.getenv('APPSEC_DEBUG') == 'true':
            timeout_msg += "\n\n**Debug Info**: AI-powered remediation takes longer. Consider increasing timeout for complex fixes."
        return timeout_msg
    except Exception as e:
        error_msg = f"❌ Auto-remediation failed: {str(e)}"
        if os.getenv('APPSEC_DEBUG') == 'true':
            error_msg += f"\n\n**Debug Info**:\n- Repo: {resolved}\n- Check the AI provider key (OPENAI_API_KEY or ANTHROPIC_API_KEY) in the server environment\n- Check GITHUB_TOKEN has 'repo' permissions\n- Verify git user config: git config --global user.name"
        return error_msg


@mcp_app.tool()
def get_report(repo_path: str) -> str:
    """Display the detailed security report with all findings, severity
    breakdown, and file locations (pr-findings.txt summary)."""
    core = _core()
    resolved = _resolve(repo_path)
    outputs_path = core._get_repo_output_path(resolved)
    pr_findings = os.path.join(outputs_path, "pr-findings.txt")

    if os.path.exists(pr_findings):
        with open(pr_findings) as f:
            content = f.read()
        return f"""# 📊 Security Report Summary

{content}

**HTML Report**: `{os.path.join(outputs_path, 'report.html')}`

**Status**: ✅ Report available
"""
    return """# 📊 No Report Available

Run `scan_repository` first to generate a security report.
"""


@mcp_app.tool()
def generate_sbom(repo_path: str) -> str:
    """Display Software Bill of Materials in CycloneDX and SPDX formats for
    compliance (SOC2, FedRAMP, ISO 27001)."""
    core = _core()
    resolved = _resolve(repo_path)
    outputs_path = core._get_repo_output_path(resolved)
    sbom_dir = os.path.join(outputs_path, "sbom")
    cyclone_path = os.path.join(sbom_dir, "sbom.cyclonedx.json")
    spdx_path = os.path.join(sbom_dir, "sbom.spdx.json")

    cyclone_data = core._load_json(cyclone_path)
    spdx_data = core._load_json(spdx_path)
    if cyclone_data is not None and spdx_data is not None:
        components = len(cyclone_data.get("components", []))
        packages = len(spdx_data.get("packages", []))
        return f"""# 📋 Software Bill of Materials (SBOM)

**Repository**: {os.path.basename(resolved)}

## 📊 SBOM Summary:
• **CycloneDX Format**: {components} components
• **SPDX Format**: {packages} packages

## 📁 Generated Files:
• **CycloneDX**: `{cyclone_path}`
• **SPDX**: `{spdx_path}`

## ✅ Compliance Benefits:
• **Supply Chain Visibility**: Complete component inventory
• **License Compliance**: SPDX format for legal requirements
• **Vulnerability Tracking**: CycloneDX for security analysis
• **Regulatory Compliance**: SOC2, FedRAMP, ISO 27001 ready

**Status**: ✅ SBOM generated successfully
"""
    return """# 📋 No SBOM Available

Run `scan_repository` first to generate SBOM files.
"""


@mcp_app.tool()
def cross_file_analysis(repo_path: str) -> str:
    """Multi-file attack chain detection across 10+ languages. Shows how
    vulnerabilities connect across files to form exploitable paths."""
    core = _core()
    resolved = _resolve(repo_path)
    pr_findings = os.path.join(core._get_repo_output_path(resolved), "pr-findings.txt")

    if os.path.exists(pr_findings):
        with open(pr_findings) as f:
            content = f.read()

        tech_stack = ""
        analysis_result = ""
        for line in content.split('\n'):
            if "Tech Stack:" in line:
                tech_stack = line.split("Tech Stack:")[-1].strip()
            elif "Cross-file Analysis:" in line:
                analysis_result = line.split("Cross-file Analysis:")[-1].strip()

        return f"""# 🔗 Cross-File Vulnerability Analysis

**Repository**: {os.path.basename(resolved)}

## 🏗️ Technology Stack: {tech_stack}

## ⚔️ Attack Chain Analysis: {analysis_result}

**Status**: ✅ AI-enhanced cross-file analysis completed
"""
    return """# 🔗 No Analysis Available

Run `scan_repository` first to generate cross-file analysis.
"""


@mcp_app.tool()
def assess_business_impact(repo_path: str) -> str:
    """Business-focused risk assessment with financial impact, compliance
    risk, and remediation timeline recommendations."""
    core = _core()
    resolved = _resolve(repo_path)
    pr_findings = os.path.join(core._get_repo_output_path(resolved), "pr-findings.txt")

    if os.path.exists(pr_findings):
        with open(pr_findings) as f:
            content = f.read()

        critical = high = total = 0
        for line in content.split('\n'):
            try:
                if "Critical:" in line:
                    critical = int(line.split()[-1])
                elif "High:" in line:
                    high = int(line.split()[-1])
                elif "security findings detected" in line:
                    total = int(line.split()[1])
            except (ValueError, IndexError):
                continue

        if critical > 0:
            risk_level = "🔴 **HIGH RISK**"
            recommendation = "Priority remediation within 1 week"
        elif high > 10:
            risk_level = "🟠 **MEDIUM RISK**"
            recommendation = "Schedule remediation within 30 days"
        else:
            risk_level = "🟡 **LOW RISK**"
            recommendation = "Monitor and maintain security posture"

        return f"""# 🎯 Business Impact Assessment

**Repository**: {os.path.basename(resolved)}
**Risk Level**: {risk_level}

## 📊 Security Metrics:
• **Total Vulnerabilities**: {total}
• **Critical Issues**: {critical}
• **High Priority**: {high}

## 💼 Business Impact:
• **Financial Risk**: {'High' if critical > 0 else 'Medium' if high > 5 else 'Low'}
• **Compliance Risk**: {'Critical' if critical > 5 else 'Moderate' if high > 0 else 'Low'}

## 🎯 Recommendation: {recommendation}

**Status**: ✅ AI-powered risk assessment completed
"""
    return """# 🎯 No Assessment Available

Run `scan_repository` first to generate business impact assessment.
"""


@mcp_app.tool()
def view_report_html(repo_path: str) -> str:
    """Open the HTML security report in the default browser. Includes
    executive summary, detailed findings, cross-file analysis, and SBOM."""
    core = _core()
    resolved = _resolve(repo_path)
    report_path = os.path.join(core._get_repo_output_path(resolved), "report.html")

    if os.path.exists(report_path):
        try:
            subprocess.run(["open", report_path], check=True)  # macOS
            return f"""# 🌐 HTML Report Opened!

**Report Location**: `{report_path}`

## 📊 Report Includes:
• **Executive Summary** - High-level risk overview
• **Detailed Findings** - Every vulnerability with context
• **Cross-File Analysis** - Attack chain visualization
• **SBOM Downloads** - CycloneDX and SPDX formats
• **Remediation Guidance** - Step-by-step fixes

**Status**: ✅ Report opened in default browser
"""
        except Exception as e:
            return f"""# 🌐 Report Available

**Report Location**: `{report_path}`

Could not auto-open browser: {str(e)}

**Manual access**: Open the file path above in your browser

**Status**: ⚠️ Manual open required
"""
    return """# 🌐 No HTML Report Available

Run `scan_repository` first to generate the HTML security report.

**Example**: "Scan nodejs-goof for vulnerabilities"
"""


@mcp_app.tool()
def get_scan_findings(repo_path: str, page: int = 1, page_size: int = 10,
                      severity_filter: str | None = None,
                      tool_filter: str | None = None,
                      category_filter: str | None = None) -> str:
    """Get detailed vulnerability findings with file paths, line numbers, and
    remediation guidance. Paginated; filter by severity
    (critical|high|medium|low), tool (semgrep|gitleaks|trivy), or category
    (security|code_quality)."""
    core = _core()
    resolved = _resolve(repo_path)
    if core.is_scan_running(resolved):
        return _scan_in_progress_response()

    raw_dir = core.raw_dir(resolved)
    all_findings = []

    semgrep_data = core._load_json(os.path.join(raw_dir, "semgrep.json"))
    if semgrep_data:
        for idx, r in enumerate(semgrep_data.get('results', [])):
            all_findings.append(_normalize_semgrep(r, idx))

    gitleaks_data = core._load_json(os.path.join(raw_dir, "gitleaks.json"))
    if isinstance(gitleaks_data, list):
        for idx, r in enumerate(gitleaks_data):
            all_findings.append(_normalize_gitleaks(r, idx))

    trivy_data = core._load_json(os.path.join(raw_dir, "trivy-sca.json"))
    if trivy_data:
        all_findings.extend(_iter_trivy_findings(trivy_data))

    all_findings.extend(_collect_code_quality_findings(core, resolved))

    # Apply filters
    filtered = all_findings
    if severity_filter:
        filtered = [f for f in filtered if f.get('severity') == severity_filter.lower()]
    if tool_filter:
        filtered = [f for f in filtered if f.get('tool') == tool_filter.lower()]
    if category_filter:
        filtered = [f for f in filtered if f.get('category') == category_filter.lower()]

    page_findings, page, page_size, total, total_pages = _paginate(filtered, page, page_size)

    result = {
        "page": page,
        "page_size": page_size,
        "total_findings": total,
        "total_pages": total_pages,
        "filters_applied": {
            "severity": severity_filter,
            "tool": tool_filter,
            "category": category_filter
        },
        "findings": page_findings
    }

    return f"""# 🔍 Scan Findings - Page {page}/{total_pages}

**Repository**: {os.path.basename(resolved)}
**Total Findings**: {total}
**Showing**: {len(page_findings)} findings on this page

{json.dumps(result, indent=2)}

**Status**: ✅ Findings retrieved successfully
"""


@mcp_app.tool()
def get_semgrep_findings(repo_path: str, page: int = 1, page_size: int = 10,
                         severity_filter: str | None = None) -> str:
    """Get paginated Semgrep SAST findings as structured JSON, with CWE/OWASP
    mappings and remediation."""
    core = _core()
    resolved = _resolve(repo_path)
    if core.is_scan_running(resolved):
        return _scan_in_progress_response()

    findings = []
    semgrep_data = core._load_json(os.path.join(core.raw_dir(resolved), "semgrep.json"))
    if semgrep_data:
        findings = [_normalize_semgrep(r, idx) for idx, r in enumerate(semgrep_data.get('results', []))]

    if severity_filter:
        findings = [f for f in findings if f['severity'] == severity_filter.lower()]

    page_findings, page, page_size, total, total_pages = _paginate(findings, page, page_size)
    return json.dumps({
        "success": True,
        "tool": "semgrep",
        "repository": os.path.basename(resolved),
        "page": page,
        "page_size": page_size,
        "total_findings": total,
        "total_pages": total_pages,
        "filters_applied": {"severity": severity_filter},
        "findings": page_findings,
        "timestamp": _timestamp()
    }, indent=2)


@mcp_app.tool()
def get_trivy_findings(repo_path: str, page: int = 1, page_size: int = 10,
                       severity_filter: str | None = None,
                       fix_available: bool | None = None) -> str:
    """Get paginated Trivy findings as structured JSON: dependency CVEs
    (packages, versions, fix info) plus IaC/config misconfigurations
    (finding_type "misconfiguration" with resolution guidance)."""
    core = _core()
    resolved = _resolve(repo_path)
    if core.is_scan_running(resolved):
        return _scan_in_progress_response()

    findings = []
    trivy_data = core._load_json(os.path.join(core.raw_dir(resolved), "trivy-sca.json"))
    if trivy_data:
        findings = _iter_trivy_findings(trivy_data)

    if severity_filter:
        findings = [f for f in findings if f['severity'] == severity_filter.lower()]
    if fix_available is not None:
        findings = [f for f in findings if f['fix_available'] == fix_available]

    page_findings, page, page_size, total, total_pages = _paginate(findings, page, page_size)
    return json.dumps({
        "success": True,
        "tool": "trivy",
        "repository": os.path.basename(resolved),
        "page": page,
        "page_size": page_size,
        "total_findings": total,
        "total_pages": total_pages,
        "filters_applied": {"severity": severity_filter, "fix_available": fix_available},
        "findings": page_findings,
        "timestamp": _timestamp()
    }, indent=2)


@mcp_app.tool()
def get_gitleaks_findings(repo_path: str, page: int = 1, page_size: int = 10) -> str:
    """Get paginated Gitleaks secret/credential findings as structured JSON:
    detected secrets, locations, and remediation steps."""
    core = _core()
    resolved = _resolve(repo_path)
    if core.is_scan_running(resolved):
        return _scan_in_progress_response()

    findings = []
    gitleaks_data = core._load_json(os.path.join(core.raw_dir(resolved), "gitleaks.json"))
    if isinstance(gitleaks_data, list):
        for idx, data in enumerate(gitleaks_data):
            f = _normalize_gitleaks(data, idx)
            # Per-tool endpoint includes extra secret metadata
            f.update({
                "rule_id": data.get('RuleID', 'Unknown'),
                "commit": data.get('Commit', 'Unknown'),
                "author": data.get('Author', 'Unknown'),
                "date": data.get('Date', 'Unknown'),
            })
            f.pop('code_snippet', None)  # do not echo the secret back
            findings.append(f)

    page_findings, page, page_size, total, total_pages = _paginate(findings, page, page_size)
    return json.dumps({
        "success": True,
        "tool": "gitleaks",
        "repository": os.path.basename(resolved),
        "page": page,
        "page_size": page_size,
        "total_findings": total,
        "total_pages": total_pages,
        "findings": page_findings,
        "timestamp": _timestamp()
    }, indent=2)


@mcp_app.tool()
def get_code_quality_findings(repo_path: str, page: int = 1, page_size: int = 10,
                              linter_filter: str | None = None) -> str:
    """Get paginated code quality findings from all linters (eslint, pylint,
    checkstyle, golangci-lint, rubocop, clippy, phpstan) as structured JSON."""
    core = _core()
    resolved = _resolve(repo_path)

    findings = _collect_code_quality_findings(core, resolved, linter_filter)
    page_findings, page, page_size, total, total_pages = _paginate(findings, page, page_size)
    return json.dumps({
        "success": True,
        "tool": "code_quality",
        "repository": os.path.basename(resolved),
        "page": page,
        "page_size": page_size,
        "total_findings": total,
        "total_pages": total_pages,
        "filters_applied": {"linter": linter_filter},
        "findings": page_findings,
        "timestamp": _timestamp()
    }, indent=2)


@mcp_app.tool()
def get_sbom_data(repo_path: str, format: str = "both") -> str:
    """Get Software Bill of Materials as structured JSON. format:
    cyclonedx|spdx|both."""
    core = _core()
    resolved = _resolve(repo_path)
    sbom_dir = os.path.join(core._get_repo_output_path(resolved), "sbom")

    result: dict[str, Any] = {
        "success": True,
        "repository": os.path.basename(resolved),
        "format": format,
        "sbom": {}
    }
    if format in ('cyclonedx', 'both'):
        data = core._load_json(os.path.join(sbom_dir, "sbom.cyclonedx.json"))
        if data is not None:
            result["sbom"]["cyclonedx"] = data
    if format in ('spdx', 'both'):
        data = core._load_json(os.path.join(sbom_dir, "sbom.spdx.json"))
        if data is not None:
            result["sbom"]["spdx"] = data
    result["timestamp"] = _timestamp()
    return json.dumps(result, indent=2)


@mcp_app.tool()
def health_check() -> str:
    """Verify MCP server health, scanner availability, and configuration.
    Use when troubleshooting setup issues or verifying installation."""
    core = _core()
    checks = []
    overall_status = "✅ Healthy"

    if os.path.exists(os.path.join(core.appsec_galaxy_path, "src", "appsec_galaxy", "main.py")):
        checks.append("✅ AppSec Galaxy installation: Found")
    else:
        checks.append(f"❌ AppSec Galaxy installation: Not found at {core.appsec_galaxy_path}")
        overall_status = "❌ Unhealthy"

    python_exe = core._find_python_executable()
    try:
        result = subprocess.run([python_exe, "--version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            checks.append(f"✅ Python: {result.stdout.strip()}")
        else:
            checks.append("⚠️ Python: Found but version check failed")
    except Exception as e:
        checks.append(f"❌ Python: Error - {str(e)}")
        overall_status = "❌ Unhealthy"

    scanners = {
        'semgrep': 'Semgrep (SAST)',
        'gitleaks': 'Gitleaks (Secrets)',
        'trivy': 'Trivy (Dependencies)'
    }
    for binary, name in scanners.items():
        if shutil.which(binary):
            try:
                result = subprocess.run([binary, '--version'], capture_output=True, text=True, timeout=5)
                version_line = result.stdout.split('\n')[0] if result.stdout else "unknown version"
                checks.append(f"✅ {name}: {version_line}")
            except Exception:
                checks.append(f"✅ {name}: Found (version check failed)")
        else:
            checks.append(f"❌ {name}: Not found in PATH")
            overall_status = "⚠️ Degraded"

    ai_provider = (os.getenv('AI_PROVIDER', '').strip().lower() or 'openai')
    ai_key_env = 'ANTHROPIC_API_KEY' if ai_provider == 'anthropic' else 'OPENAI_API_KEY'
    if os.getenv(ai_key_env):
        checks.append(f"✅ AI provider ({ai_provider}): {ai_key_env} configured")
    else:
        checks.append(f"⚠️ AI provider ({ai_provider}): {ai_key_env} not configured (AI features unavailable)")

    if os.getenv('GITHUB_TOKEN'):
        checks.append("✅ GitHub Token: Configured")
    else:
        checks.append("⚠️ GitHub Token: Not configured (PR creation won't work)")

    checks.append(f"📊 Scan Level: {os.getenv('APPSEC_SCAN_LEVEL', 'critical-high')}")
    checks.append(f"🐛 Debug Mode: {os.getenv('APPSEC_DEBUG', 'false')}")
    checks.append(f"⏱️ Timeouts: Scan={os.getenv('MCP_SCAN_TIMEOUT', '300')}s, Remediate={os.getenv('MCP_REMEDIATE_TIMEOUT', '600')}s")

    search_paths = core._find_repo_search_paths()
    accessible = [p for p in search_paths if os.path.exists(p)]
    checks.append(f"📁 Repository Search Paths: {len(accessible)}/{len(search_paths)} accessible")

    recommendations = []
    if any("❌" in c and "Gitleaks" in c for c in checks):
        recommendations.append("• Install Gitleaks: `brew install gitleaks` (macOS) or see https://github.com/gitleaks/gitleaks")
    if any("❌" in c and "Trivy" in c for c in checks):
        recommendations.append("• Install Trivy: `brew install trivy` (macOS) or see https://trivy.dev/getting-started/installation/")
    if any("❌" in c and "Semgrep" in c for c in checks):
        recommendations.append("• Install Semgrep: `pip install semgrep` (should be auto-installed with AppSec Galaxy)")
    if any("⚠️" in c and "AI provider" in c for c in checks):
        recommendations.append("• Configure the AI provider key (OPENAI_API_KEY or ANTHROPIC_API_KEY) in the MCP server environment")
    if any("⚠️" in c and "GitHub" in c for c in checks):
        recommendations.append("• Configure GITHUB_TOKEN in mcp/mcp_env for PR creation")
    if not recommendations:
        recommendations.append("• All critical components are healthy! ✅")

    checks_formatted = '\n'.join([f"  {check}" for check in checks])
    return f"""# 🏥 AppSec Galaxy MCP Health Check

**Overall Status**: {overall_status}

## System Checks:
{checks_formatted}

## Configuration:
- **AppSec Galaxy Path**: `{core.appsec_galaxy_path}`
- **MCP Server**: FastMCP (official MCP SDK)
- **Available Tools**: 16

## Recommendations:
{chr(10).join(recommendations)}

**Status**: Health check completed at {time.strftime('%Y-%m-%d %H:%M:%S')}
"""


@mcp_app.tool()
def analyze_dependency_health(repo_path: str, include_healthy: bool = True) -> str:
    """Analyze dependency code paths: usage tracing, embedding depth
    (trivial/shallow/moderate/deep), package health (healthy/stale/abandoned),
    and recommended strategy (keep/upgrade/inline/replace/remove)."""
    resolved = _resolve(repo_path)

    try:
        from appsec_galaxy.dependency_analyzer import run_dependency_analysis
    except ImportError:
        return "❌ Dependency analysis module not available. Ensure AppSec Galaxy is installed."

    report = run_dependency_analysis(resolved)
    if report is None:
        return "⚠️ Dependency analysis is disabled. Set APPSEC_DEPENDENCY_ANALYSIS=true to enable."
    if report.analyzed_dependencies == 0:
        return "📦 No dependencies found in this repository."

    lines = [
        "# 📦 Dependency Health Report",
        "",
        f"**Repository:** `{resolved}`",
        f"**Total Dependencies:** {report.total_dependencies}",
        f"**Analyzed:** {report.analyzed_dependencies}",
        "",
        "## Health Breakdown",
    ]
    for status, count in sorted(report.health_breakdown.items()):
        icon = {'healthy': '🟢', 'stale': '🟡', 'abandoned': '🟠', 'vulnerable': '🔴', 'dead': '⚫', 'unknown': '⚪'}.get(status, '⚪')
        lines.append(f"- {icon} **{status}**: {count}")

    lines.extend(["", "## Depth Breakdown"])
    for cat, count in sorted(report.depth_breakdown.items()):
        lines.append(f"- **{cat}**: {count}")

    lines.extend(["", "## Strategy Breakdown"])
    for strategy, count in sorted(report.strategy_breakdown.items()):
        icon = {'keep': '✅', 'upgrade': '⬆️', 'inline': '📝', 'replace': '🔄', 'remove': '🗑️'}.get(strategy, '•')
        lines.append(f"- {icon} **{strategy}**: {count}")

    actionable = [d for d in report.dependencies if d.remediation_strategy != 'keep']
    if actionable:
        lines.extend(["", "## Action Items"])
        for dep in actionable[:15]:
            replacement = f" → {dep.replacement_suggestion}" if dep.replacement_suggestion else ""
            lines.append(
                f"- **{dep.package_name}** ({dep.ecosystem}): "
                f"{dep.remediation_strategy}{replacement} "
                f"[{dep.health_status}, {dep.depth_category}, {len(dep.files_using)} files]"
            )

    if include_healthy and report.dependencies:
        lines.extend(["", "## All Dependencies"])
        for dep in report.dependencies[:30]:
            lines.append(
                f"- **{dep.package_name}** {dep.installed_version or ''}: "
                f"{dep.health_status} | {dep.depth_category} (score: {dep.depth_score}) | "
                f"strategy: {dep.remediation_strategy}"
            )

    return '\n'.join(lines)


@mcp_app.tool()
def get_dependency_usage(repo_path: str, package_name: str) -> str:
    """Get detailed usage analysis for one dependency: import sites, call
    sites, APIs used, depth score, health status, remediation strategy."""
    resolved = _resolve(repo_path)
    if not package_name:
        return "❌ Please provide a package_name parameter."

    try:
        from appsec_galaxy.dependency_analyzer import run_dependency_analysis
    except ImportError:
        return "❌ Dependency analysis module not available."

    report = run_dependency_analysis(resolved)
    if report is None:
        return "⚠️ Dependency analysis is disabled."

    match = None
    for dep in report.dependencies:
        if dep.package_name.lower() == package_name.lower():
            match = dep
            break
    if match is None:
        for dep in report.dependencies:
            if package_name.lower() in dep.package_name.lower():
                match = dep
                break
    if match is None:
        available = ', '.join(sorted(d.package_name for d in report.dependencies[:20]))
        return f"❌ Package '{package_name}' not found in dependencies.\n\nAvailable: {available}"

    lines = [
        f"# 📦 {match.package_name}",
        "",
        "| Property | Value |",
        "|---|---|",
        f"| **Ecosystem** | {match.ecosystem} |",
        f"| **Version** | {match.installed_version or 'unknown'} |",
        f"| **Manifest** | {match.manifest_file} |",
        f"| **Health** | {match.health_status} |",
        f"| **Depth Score** | {match.depth_score} ({match.depth_category}) |",
        f"| **Strategy** | {match.remediation_strategy} |",
        f"| **Files Using** | {len(match.files_using)} |",
        f"| **APIs Used** | {len(match.unique_apis_used)} |",
        f"| **Import Sites** | {len(match.import_sites)} |",
        f"| **Call Sites** | {len(match.call_sites)} |",
    ]
    if match.replacement_suggestion:
        lines.append(f"| **Replacement** | {match.replacement_suggestion} |")
    if match.has_cve:
        lines.append("| **Has CVE** | Yes |")
        if match.fixed_version:
            lines.append(f"| **Fixed Version** | {match.fixed_version} |")

    if match.files_using:
        lines.extend(["", "## Files Using This Dependency"])
        for f in sorted(match.files_using)[:20]:
            lines.append(f"- `{f}`")

    if match.unique_apis_used:
        lines.extend(["", "## APIs Used"])
        for api in sorted(match.unique_apis_used)[:20]:
            lines.append(f"- `{api}`")

    if match.import_sites:
        lines.extend(["", "## Import Sites"])
        for site in match.import_sites[:10]:
            lines.append(f"- `{site.get('file', '')}:{site.get('line', '')}`: {', '.join(site.get('imported_names', []))}")

    if match.health_info:
        lines.extend(["", "## Health Details"])
        for k, v in match.health_info.items():
            lines.append(f"- **{k}**: {v}")

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# MCP resources: scan artifacts readable directly (no tool call round-trip).
# {repo} is a repository name or path (same smart discovery as the tools).
# ---------------------------------------------------------------------------

def _read_artifact(repo: str, relative_path: str, description: str) -> str:
    core = _core()
    resolved = core.find_repo(_validate_repo_arg(repo))
    artifact = os.path.join(core._get_repo_output_path(resolved), relative_path)
    if not os.path.exists(artifact):
        return f"{description} not found for '{os.path.basename(resolved)}'. Run scan_repository first."
    with open(artifact, encoding='utf-8', errors='replace') as f:
        return f.read()


@mcp_app.resource("appsec-galaxy://{repo}/report.html")
def resource_report_html(repo: str) -> str:
    """Full HTML security report for a scanned repository."""
    return _read_artifact(repo, "report.html", "HTML report")


@mcp_app.resource("appsec-galaxy://{repo}/report.sarif")
def resource_report_sarif(repo: str) -> str:
    """SARIF 2.1.0 findings log for a scanned repository."""
    return _read_artifact(repo, "report.sarif", "SARIF report")


@mcp_app.resource("appsec-galaxy://{repo}/sbom.cyclonedx.json")
def resource_sbom_cyclonedx(repo: str) -> str:
    """CycloneDX SBOM for a scanned repository."""
    return _read_artifact(repo, os.path.join("sbom", "sbom.cyclonedx.json"), "CycloneDX SBOM")


@mcp_app.resource("appsec-galaxy://{repo}/sbom.spdx.json")
def resource_sbom_spdx(repo: str) -> str:
    """SPDX SBOM for a scanned repository."""
    return _read_artifact(repo, os.path.join("sbom", "sbom.spdx.json"), "SPDX SBOM")


def main():
    """Entry point: run the MCP server over stdio."""
    _core()  # Fail fast at startup if the AppSec Galaxy installation is missing
    mcp_app.run()


if __name__ == "__main__":
    main()
