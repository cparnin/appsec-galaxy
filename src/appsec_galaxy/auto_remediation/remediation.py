"""AI-powered auto-remediation for AppSec Galaxy findings (OpenAI or Anthropic)."""

import os
import json
import subprocess
from pathlib import Path
from typing import Any
from datetime import datetime
import logging
import re
import shlex

# Import configuration constants
from appsec_galaxy.config import PROTECTED_FILE_PATTERNS
from appsec_galaxy.scanners.ai_scanner import _call_ai

logger = logging.getLogger(__name__)

def validate_package_name(name: str) -> bool:
    """
    Validate package name contains only safe characters to prevent command injection.

    Allows:
    - Alphanumeric characters
    - Dots, hyphens, underscores, forward slashes
    - @ symbol for scoped packages (npm) and version specs
    - Colon for namespaced packages (some ecosystems)

    Args:
        name: Package name to validate

    Returns:
        bool: True if name is safe, False otherwise
    """
    if not name or not isinstance(name, str):
        return False

    # Length check to prevent resource exhaustion
    if len(name) > 200:
        return False

    # Allow alphanumeric, dots, hyphens, underscores, forward slashes, @ and :
    # This covers most package naming conventions across ecosystems
    pattern = r'^[a-zA-Z0-9._/@:-]+$'

    if not re.match(pattern, name):
        return False

    # Additional security checks
    dangerous_patterns = [
        r'\.\.', r'//', r'\\', r'\$', r'`', r'\|', r'&', r';', r'>', r'<',
        r'\s', r'\n', r'\r', r'\t'  # No whitespace or control characters
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, name):
            return False

    return True

def validate_version_string(version: str) -> bool:
    """
    Validate version string contains only safe characters to prevent command injection.
    Supports comma-separated multiple versions.

    Allows:
    - Alphanumeric characters
    - Dots, hyphens for semantic versioning
    - Caret (^) and tilde (~) for version ranges
    - Comparison operators (>=, >, <=, <, =)
    - Plus (+) for build metadata
    - Commas and spaces for multiple versions

    Args:
        version: Version string to validate (can be comma-separated)

    Returns:
        bool: True if version is safe, False otherwise
    """
    if not version or not isinstance(version, str):
        return False

    # Length check (increased for multiple versions)
    if len(version) > 200:
        return False

    # Split by comma and validate each version
    versions = [v.strip() for v in version.split(',')]

    for v in versions:
        if not v:  # Skip empty versions
            continue

        # Allow semantic versioning patterns with range operators and spaces
        pattern = r'^[a-zA-Z0-9._+^~>=<\s-]+$'

        if not re.match(pattern, v):
            return False

        # Additional security checks - no dangerous characters
        dangerous_patterns = [
            r'\$', r'`', r'\|', r'&', r';', r'\\', r'"', r"'",
            r'\n', r'\r', r'\t'  # No control characters (but allow spaces)
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, v):
                return False

    return True

def validate_file_path(file_path: str) -> bool:
    """
    Validate file path to prevent directory traversal and other path-based attacks.

    Args:
        file_path: File path to validate

    Returns:
        bool: True if path is safe, False otherwise
    """
    if not file_path or not isinstance(file_path, str):
        return False

    # Length check
    if len(file_path) > 1000:
        return False

    # No path traversal attempts
    dangerous_patterns = [
        r'\.\.', r'//+', r'\\\\+', r'\$', r'`', r'\|', r'&', r';',
        r'\n', r'\r', r'\t'  # No control characters
    ]

    for pattern in dangerous_patterns:
        if re.search(pattern, file_path):
            return False

    return True

def sanitize_git_message(message: str) -> str:
    """
    Sanitize strings used in git commit messages and PR titles to prevent injection.

    Args:
        message: String to sanitize

    Returns:
        str: Sanitized string safe for use in git commands
    """
    if not message or not isinstance(message, str):
        return ""

    # Length limit for practical purposes
    if len(message) > 1000:
        message = message[:1000] + "..."

    # Replace dangerous characters with spaces to maintain readability
    # This prevents command injection while keeping messages readable
    sanitized = re.sub(r'[`$\|&;"\'\\\n\r\t]', ' ', message)

    # Replace multiple spaces with single space
    sanitized = re.sub(r'\s+', ' ', sanitized)

    return sanitized.strip()

def sanitize_markdown_field(text: Any, max_len: int = 200) -> str:
    """Neutralize untrusted text for interpolation into a PR body.

    PR titles go through sanitize_git_message (which flattens newlines), but
    PR *bodies* are multi-line Markdown rendered on GitHub, and the finding
    text, file paths, package names, and AI summaries interpolated into them
    all originate from the scanned repo (hostile input). Without neutralizing,
    an attacker can inject Markdown links/images (tracking pixels, phishing),
    @mentions (notification spam), raw HTML, or code-fence breakouts, or fake
    instructions aimed at a reviewer or a downstream LLM reading the PR.

    This keeps the text readable but defuses the active Markdown/HTML
    constructs: it is meant for a single inline field, so newlines collapse
    to spaces.
    """
    s = str(text) if text is not None else ""
    s = s.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ')
    if len(s) > max_len:
        s = s[:max_len] + '...'
    s = s.replace('\\', ' ')  # drop backslash escapes
    # Strip link-text/HTML/code-fence/table-cell forming characters
    for ch in ('`', '[', ']', '<', '>', '|'):
        s = s.replace(ch, ' ')
    # Defang autolinked URLs and @mentions so they render as inert text.
    # The replacement must not reintroduce Markdown-active characters.
    s = re.sub(r'(?i)\b(https?|ftp|file|data)://', r'\1 (scheme) ', s)
    s = re.sub(r'(?<![\w/])@(\w)', r'@ \1', s)
    return re.sub(r'\s+', ' ', s).strip()


def validate_vulnerability_type(vuln_type: str) -> bool:
    """
    Validate vulnerability type string to prevent injection.

    Args:
        vuln_type: Vulnerability type string

    Returns:
        bool: True if safe, False otherwise
    """
    if not vuln_type or not isinstance(vuln_type, str):
        return False

    # Length check
    if len(vuln_type) > 200:
        return False

    # Allow alphanumeric, dots, hyphens, underscores, colons, spaces
    pattern = r'^[a-zA-Z0-9._:\s-]+$'

    if not re.match(pattern, vuln_type):
        return False

    return True

def _secure_file_path(repo_path: str, file_path: str) -> str | None:
    """
    Securely validate and construct file path to prevent path traversal.

    Args:
        repo_path: Repository root path
        file_path: Relative file path from findings

    Returns:
        str: Validated full path or None if invalid
    """
    try:
        # Input validation
        if not file_path or not isinstance(file_path, str):
            logger.error("Invalid file path in finding")
            return None

        # Remove null bytes and dangerous characters
        clean_path = file_path.replace('\x00', '')
        if clean_path != file_path:
            logger.error("Invalid characters in file path")
            return None

        # Check for path traversal attempts (but allow absolute paths from scanners)
        if '..' in clean_path:
            logger.error(f"Path traversal attempt detected: {clean_path}")
            return None

        # Handle absolute paths from scanners (convert to relative)
        if clean_path.startswith('/'):
            repo_path_obj = Path(repo_path).resolve()
            clean_path_obj = Path(clean_path).resolve()

            # Check if the absolute path is within the repository
            try:
                relative_path = clean_path_obj.relative_to(repo_path_obj)
                clean_path = str(relative_path)
            except ValueError:
                logger.error(f"File path outside repository: {clean_path}")
                return None

        # Construct full path safely
        repo_path_obj = Path(repo_path).resolve()
        full_path = repo_path_obj / clean_path
        full_path = full_path.resolve()

        # Ensure the resolved path is within the repository
        if not str(full_path).startswith(str(repo_path_obj)):
            logger.error(f"File path escapes repository boundary: {clean_path}")
            return None

        # Check if file exists
        if not full_path.exists():
            logger.warning(f"File not found: {full_path}")
            return None

        # Validate file type (only allow text files)
        if not _is_text_file(full_path):
            logger.error(f"File is not a text file: {full_path}")
            return None

        return str(full_path)

    except Exception as e:
        logger.error(f"Error validating file path: {e}")
        return None

def _is_text_file(file_path: Path) -> bool:
    """Check if file is a text file safe to read."""
    try:
        # Check file size (limit to 10MB)
        if file_path.stat().st_size > 10 * 1024 * 1024:
            logger.error(f"File too large: {file_path}")
            return False

        # Check file extension
        text_extensions = {
            '.py', '.js', '.ts', '.java', '.c', '.cpp', '.h', '.cs',
            '.go', '.rs', '.php', '.rb', '.scala', '.kt', '.swift',
            '.html', '.css', '.xml', '.json', '.yaml', '.yml', '.md',
            '.txt', '.cfg', '.conf', '.ini', '.properties'
        }

        if file_path.suffix.lower() not in text_extensions:
            # Try to detect text file by reading first 1024 bytes
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                # Check for null bytes (binary file indicator)
                if b'\x00' in chunk:
                    return False

        return True

    except Exception as e:
        logger.error(f"Error checking file type: {e}")
        return False

def _secure_read_file(file_path: str, max_size: int = 10 * 1024 * 1024) -> str | None:
    """
    Securely read file content with size limits.

    Args:
        file_path: Path to file to read
        max_size: Maximum file size in bytes

    Returns:
        str: File content or None if failed
    """
    try:
        path = Path(file_path)

        # Check file size
        if path.stat().st_size > max_size:
            logger.error(f"File too large to read: {path}")
            return None

        with open(path, encoding='utf-8', errors='replace') as f:
            content = f.read()

        # Additional size check after reading
        if len(content) > max_size:
            logger.error(f"File content too large: {path}")
            return None

        return content

    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return None


# Parse-only syntax validators, keyed by file extension. Every command is a
# lint/parse mode that does NOT execute the file, so it is safe to run against
# hostile repo contents (the scanner assumes scanned code is untrusted).
# Missing tools are handled as "unknown" (cannot validate) rather than failing.
_SYNTAX_CHECK_CMD = {
    '.js': ['node', '--check'],
    '.jsx': ['node', '--check'],
    '.mjs': ['node', '--check'],
    '.cjs': ['node', '--check'],
    '.json': None,   # validated in-process via json.loads
    '.py': None,     # validated in-process via ast.parse
    '.yaml': None,   # validated in-process via yaml.safe_load (if available)
    '.yml': None,
    '.sh': ['bash', '-n'],
    '.bash': ['bash', '-n'],
    '.rb': ['ruby', '-c'],
    '.php': ['php', '-l'],
    '.go': ['gofmt', '-e'],
}


def validate_file_syntax(abs_path: str) -> str:
    """Return 'ok', 'broken', or 'unknown' for a file's syntactic validity.

    This is the safety gate that stops auto-remediation from committing a fix
    that breaks the file (e.g. a single-line replacement that truncates a
    multi-line statement). 'unknown' means no validator is available for that
    file type or the required tool is not installed; callers treat 'unknown'
    as non-blocking but should surface that the fix was not syntax-checked.
    """
    import ast as _ast
    import shutil as _shutil

    ext = os.path.splitext(abs_path)[1].lower()
    if ext not in _SYNTAX_CHECK_CMD:
        return 'unknown'

    # In-process validators (no subprocess, always available).
    if ext == '.py':
        try:
            with open(abs_path, encoding='utf-8') as fh:
                _ast.parse(fh.read())
            return 'ok'
        except SyntaxError:
            return 'broken'
        except Exception:
            return 'unknown'
    if ext == '.json':
        try:
            with open(abs_path, encoding='utf-8') as fh:
                json.load(fh)
            return 'ok'
        except json.JSONDecodeError:
            return 'broken'
        except Exception:
            return 'unknown'
    if ext in ('.yaml', '.yml'):
        try:
            import yaml as _yaml
        except ImportError:
            return 'unknown'
        try:
            with open(abs_path, encoding='utf-8') as fh:
                _yaml.safe_load(fh)
            return 'ok'
        except _yaml.YAMLError:
            return 'broken'
        except Exception:
            return 'unknown'

    # Subprocess validators (parse-only; require the tool on PATH).
    cmd = _SYNTAX_CHECK_CMD[ext]
    if not cmd or not _shutil.which(cmd[0]):
        return 'unknown'
    try:
        result = subprocess.run(
            [*cmd, abs_path],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return 'unknown'
    return 'ok' if result.returncode == 0 else 'broken'


SUMMARY_INSTRUCTIONS = """You are a senior application security advisor.
Write a concise executive summary focused on business impact, urgency, and
specific next actions. Be direct and avoid unnecessary technical jargon."""

FIX_INSTRUCTIONS = """You are an expert application security engineer.
Return only the single corrected line of code requested by the user. Do not
include a line number, Markdown, code fences, or explanatory text."""


class AutoRemediator:
    """Handles automatic remediation of SAST findings."""

    def __init__(self, ai_provider: str, model: str | None = None):
        from appsec_galaxy.scanners.ai_scanner import (
            SUPPORTED_PROVIDERS, _get_ai_client, get_default_model,
        )

        self.ai_provider = ai_provider.strip().lower()
        if self.ai_provider not in SUPPORTED_PROVIDERS:
            raise ValueError(
                f"AI_PROVIDER must be one of {', '.join(SUPPORTED_PROVIDERS)} "
                f"(got '{self.ai_provider}')"
            )

        self.model = (
            model
            or os.getenv('AI_MODEL', '').strip()
            or get_default_model(self.ai_provider)
        )
        self._logged_unsupported_types: set[str] = set()  # Track unsupported file types to reduce noise

        self.client = _get_ai_client()

    def generate_executive_summary(self, findings: list[dict[str, Any]]) -> str:
        """Generate an executive summary of security findings."""
        # Count findings by severity
        critical = len([f for f in findings if f.get('severity', '').lower() == 'critical'])
        high = len([f for f in findings if f.get('severity', '').lower() in ['high', 'error']])
        total = len(findings)

        user_input = f"""Create a concise executive summary for {total} security findings:
- {critical} critical vulnerabilities
- {high} high-severity issues

Focus on business impact and urgency. Be direct and actionable. Don't use technical jargon."""

        try:
            summary = _call_ai(
                self.client,
                self.model,
                SUMMARY_INSTRUCTIONS,
                user_input,
                300,
            ).strip()
            if not summary:
                raise ValueError("AI provider returned an empty executive summary")
            return summary
        except Exception as e:
            logger.error(f"Failed to generate executive summary: {e}")
            return f"Security scan found {total} findings ({critical} critical, {high} high severity). Immediate review recommended."

    def can_remediate(self, finding: dict[str, Any]) -> bool:
        """Check if a finding can be auto-remediated."""
        # Only SAST findings can be auto-remediated
        if finding.get('tool') != 'semgrep':
            return False

        # Get both check_id and message for pattern matching
        check_id = finding.get('check_id', '').lower()
        message = finding.get('extra', {}).get('message', '').lower()
        file_path = finding.get('path', '').lower()

        # EXCLUDE secrets detection - these need manual review, not auto-fix
        secret_patterns = [
            'generic.secrets', 'detected-secret', 'detected-jwt-token',
            'detected-api-key', 'detected-password', 'detected-private-key',
            'hardcoded-password', 'hardcoded-credential'
        ]
        for secret_pattern in secret_patterns:
            if secret_pattern in check_id:
                logger.debug(f"🔐 Cannot auto-remediate secret detection: {check_id}")
                return False

        # Check if file is protected first
        for pattern in PROTECTED_FILE_PATTERNS:
            if pattern.lower() in file_path or file_path.endswith(pattern.lower()):
                logger.debug(f"🚫 Cannot remediate protected file: {file_path} (matches: {pattern})")
                return False

        # Expanded remediable patterns that match real Semgrep rules
        remediable_patterns = [
            # Injection vulnerabilities
            'injection', 'sql-injection', 'nosql', 'nosqli', 'command-injection',
            'child-process', 'exec', 'shell-injection', 'tainted-sql-string',
            'formatted-sql-string', 'tainted-url-host',

            # XSS vulnerabilities
            'xss', 'explicit-unescape', 'template-explicit-unescape',

            # Path traversal
            'path-traversal', 'directory-traversal',

            # JWT and crypto vulnerabilities (algorithm/config issues, NOT secret detection)
            'jwt-none-alg', 'weak-crypto', 'insecure-crypto',
            'none-algorithm', 'none-alg', 'jwt-weak',

            # Session/cookie security (configuration issues)
            'session-hardcoded-secret', 'express-session',
            'cookie-session', 'express-cookie-settings',

            # Transport security
            'http-server', 'insecure-transport', 'using-http-server',

            # Prototype pollution
            'prototype-pollution', 'prototype-pollution-loop',

            # Express-specific patterns (matching actual nodejs-goof findings)
            'express-mongo-nosqli', 'mongo-nosqli', 'express-child-process',
            'express-cookie-session', 'express-check-csurf', 'csurf-middleware', 'csrf',

            # NOTE: Docker "missing-user"/"missing-user-entrypoint" findings were
            # intentionally removed. They are ADDITIVE (the fix must INSERT a
            # `USER` line), but auto-fix only does single-line REPLACEMENT, which
            # deletes the flagged line (e.g. the ENTRYPOINT) instead. These are
            # flagged for manual review until an insert-mode fixer exists.
        ]

        # Check if any pattern matches the check_id or message
        for pattern in remediable_patterns:
            if pattern in check_id or pattern in message:
                logger.debug(f"✅ Can remediate: {check_id} in {file_path}")
                return True

        logger.debug(f"❌ Cannot remediate: {check_id} in {file_path} (no matching patterns)")
        logger.debug(f"   Checked patterns: {remediable_patterns[:5]}... (total: {len(remediable_patterns)})")
        return False

    def generate_code_fix(self, finding: dict[str, Any], repo_path: str) -> dict[str, Any] | None:
        """Generate a code fix for a SAST finding."""
        try:
            file_path = finding.get('path', '')
            # Fix: Get line number from start field (Semgrep format)
            line_number = finding.get('start', {}).get('line', 0)
            message = finding.get('extra', {}).get('message', finding.get('message', ''))
            check_id = finding.get('check_id', '')

            # Validate and read the file content securely
            full_path = _secure_file_path(repo_path, file_path)
            if not full_path:
                return None

            content = _secure_read_file(full_path)
            if content is None:
                return None

            # Get the problematic line and context
            lines = content.split('\n')
            if line_number > len(lines) or line_number <= 0:
                logger.warning(f"Line number {line_number} out of range for {full_path}")
                return None

            # Get context lines (5 before and after)
            start_line = max(0, line_number - 6)  # -6 because line_number is 1-indexed
            end_line = min(len(lines), line_number + 4)  # +4 for 5 lines after

            context_lines = lines[start_line:end_line]
            problematic_line = lines[line_number - 1]  # Convert to 0-indexed

            # Generate fix using AI with more context
            context_str = '\n'.join(f"{start_line + i + 1}: {line}" for i, line in enumerate(context_lines))

            user_input = self._get_fix_prompt(
                check_id, message, file_path, line_number, context_str
            )
            fix = _call_ai(
                self.client,
                self.model,
                FIX_INSTRUCTIONS,
                user_input,
                200,
            )

            sanitized_fix = self._sanitize_model_fix(
                fix,
                check_id,
                file_path,
                line_number,
                problematic_line,
            )
            if not sanitized_fix:
                return None

            return {
                'file_path': file_path,
                'line_number': line_number,
                'original_line': problematic_line,
                'fixed_line': sanitized_fix,
                'vulnerability_type': check_id,
                'description': message
            }

        except Exception as e:
            logger.error(f"Error generating fix for finding: {e}")
            return None

    def _get_fix_prompt(self, check_id, message, file_path, line_number, context_str):
        return f"""
**Vulnerability Details:**
- **Type:** {check_id}
- **Description:** {message}
- **File:** {file_path}
- **Line:** {line_number} (The line to be replaced)

**Code Context:**
```
{context_str}
```

Provide the corrected code for line {line_number}.
"""

    def _sanitize_model_fix(
        self,
        raw_fix: str,
        check_id: str = "",
        file_path: str = "",
        line_number: int = 0,
        original_line: str = "",
    ) -> str | None:
        """Ensure model output is a single line of code without markup."""
        if not raw_fix:
            return None

        cleaned_lines = []
        for line in raw_fix.splitlines():
            token = line.strip()
            if not token or token.startswith("```"):
                continue
            cleaned_lines.append(line)

        if not cleaned_lines:
            logger.warning("⚠️  AI returned empty fix after cleaning - skipping")
            return None

        if len(cleaned_lines) != 1:
            logger.info(f"ℹ️  Complex vulnerability detected: {check_id} in {file_path}:{line_number}")
            logger.info(f"    → AI suggests {len(cleaned_lines)}-line fix (auto-fix only supports single-line replacements)")
            logger.info(f"    Manual fix required for {file_path}:{line_number}")
            return None

        indent_match = re.match(r"^[ \t]*", original_line)
        indentation = indent_match.group(0) if indent_match else ""
        candidate = indentation + cleaned_lines[0].strip()

        if any(ch in candidate for ch in ['\n', '\r']) or len(candidate) > 512:
            logger.warning(f"⚠️  Skipping {check_id}: Fix contains newlines or exceeds 512 chars (len={len(candidate)})")
            logger.warning(f"    Recommendation: Manually review {file_path}:{line_number}")
            return None

        return candidate

    def apply_fix(self, fix: dict[str, Any], repo_path: str) -> bool:
        """Apply a code fix to the file."""
        try:
            file_path = fix['file_path']
            line_number = fix['line_number']
            fixed_line = fix['fixed_line']

            logger.debug(f"Attempting to apply fix to: {file_path}")

            # PIPELINE SAFETY: Never modify protected files
            for pattern in PROTECTED_FILE_PATTERNS:
                if pattern.lower() in file_path.lower() or file_path.lower().endswith(pattern.lower()):
                    logger.warning(f"🚫 BLOCKED: Skipping fix for protected file: {file_path} (matches pattern: {pattern})")
                    return False

            full_path = os.path.join(repo_path, file_path)

            if any(ch in fixed_line for ch in ['\n', '\r']):
                logger.error(f"Refusing to apply multi-line fix to {file_path}:{line_number}")
                return False

            # Read the file
            with open(full_path, encoding='utf-8') as f:
                original_lines = f.readlines()

            if line_number > len(original_lines):
                logger.error(f"Line number {line_number} out of range for {file_path}")
                return False

            # Apply the fix to a copy so we can roll back on a bad result.
            lines = list(original_lines)
            lines[line_number - 1] = fixed_line + '\n'
            with open(full_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)

            # SAFETY GATE: never leave a fix in place that breaks the file.
            # A single-line replacement can truncate a multi-line statement or
            # otherwise produce invalid code; if the language has a validator
            # and the result no longer parses, revert and refuse the fix.
            verdict = validate_file_syntax(full_path)
            if verdict == 'broken':
                with open(full_path, 'w', encoding='utf-8') as f:
                    f.writelines(original_lines)
                logger.warning(
                    f"↩️  Reverted fix for {file_path}:{line_number}: the result "
                    f"failed syntax validation (would have committed broken code). "
                    f"Flagged for manual review."
                )
                return False

            if verdict == 'unknown':
                logger.info(
                    f"✅ Applied fix to {file_path}:{line_number} "
                    f"(no syntax validator for this file type; single-line change only)"
                )
            else:
                logger.info(
                    f"✅ Applied fix to {file_path}:{line_number} (syntax validated)"
                )
            return True

        except Exception as e:
            logger.error(f"Error applying fix: {e}")
            return False

    def create_remediation_branch(self, repo_path: str, base_branch: str = "main") -> str:
        """Create a new branch for remediation."""
        try:
            # Detect actual default branch
            detected_branch = self.get_default_branch(repo_path)
            if detected_branch:
                base_branch = detected_branch

            # Generate branch name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            branch_name = f"security-fixes-{timestamp}"

            # Switch to base branch first to ensure clean start
            subprocess.run(
                ["git", "checkout", base_branch],
                cwd=repo_path,
                check=True,
                capture_output=True
            )

            # Create and checkout new branch from clean base
            subprocess.run(
                ["git", "checkout", "-b", branch_name],
                cwd=repo_path,
                check=True,
                capture_output=True
            )

            logger.info(f"Created remediation branch: {branch_name}")
            return branch_name

        except subprocess.CalledProcessError as e:
            logger.error(f"Error creating branch: {e}")
            raise

    def commit_fixes(self, repo_path: str, fixes: list[dict[str, Any]]) -> bool:
        """Commit the applied fixes."""
        try:
            # Add all modified files
            subprocess.run(
                ["git", "add", "."],
                cwd=repo_path,
                check=True,
                capture_output=True
            )

            # Create commit message
            fix_count = len(fixes)
            commit_message = f"🔒 Auto-remediate {fix_count} security vulnerabilities\n\n"
            commit_message += "Fixed vulnerabilities:\n"

            for fix in fixes:
                # Sanitize user-controlled data to prevent injection
                vuln_type = sanitize_git_message(str(fix.get('vulnerability_type', 'Unknown')))
                file_path = sanitize_git_message(str(fix.get('file_path', 'Unknown')))
                line_num = str(fix.get('line_number', '0'))  # Numbers are safe
                commit_message += f"- {vuln_type} in {file_path}:{line_num}\n"

            # Commit
            subprocess.run(
                ["git", "commit", "-m", commit_message],
                cwd=repo_path,
                check=True,
                capture_output=True
            )

            logger.info(f"Committed {fix_count} security fixes")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Error committing fixes: {e}")
            return False

    def _generate_improved_pr_body(self, findings, fixes, branch_name):
        """Generate improved PR body with findings details."""
        # Group findings by tool
        tools = {}
        for finding in findings:
            tool = finding.get('tool', 'unknown')
            if tool not in tools:
                tools[tool] = []
            tools[tool].append(finding)

        # Count totals
        total_findings = len(findings)
        critical = len([f for f in findings if f.get('severity', '').lower() == 'critical'])
        high = len([f for f in findings if f.get('severity', '').lower() in ['high', 'error']])
        fixes_applied = len(fixes)

        # Risk assessment
        risk_level = "🟢 LOW"
        if critical > 0:
            risk_level = "🔴 CRITICAL"
        elif high > 5:
            risk_level = "🟡 HIGH"
        elif high > 0:
            risk_level = "🟠 MEDIUM"

        # Build PR body
        pr_lines = [
            "# Security Auto-Remediation",
            "",
            f"## Risk Assessment: {risk_level}",
            "",
            "**Summary:**",
            f"* {total_findings} total security findings detected",
            f"* {fixes_applied} vulnerabilities auto-fixed in this PR",
            f"* {total_findings - fixes_applied} findings require manual attention",
            "",
            "## What This PR Fixes",
        ]

        # List the specific fixes applied (fields come from the scanned repo:
        # sanitize before interpolating into Markdown, see sanitize_markdown_field)
        for fix in fixes:
            vuln_type = sanitize_markdown_field(fix.get('vulnerability_type', 'Security issue'), 80)
            file_path = sanitize_markdown_field(fix.get('file_path', 'unknown file'), 200)
            line_num = sanitize_markdown_field(fix.get('line_number', '?'), 12)
            pr_lines.append(f"* **{vuln_type}** in `{file_path}:{line_num}`")

        pr_lines.extend([
            "",
            "## Remaining Findings (Manual Review Required)",
        ])

        # Show all remaining findings that couldn't be auto-fixed
        fixed_paths_lines = set()
        for fix in fixes:
            file_path = fix.get('file_path', '')
            line_num = str(fix.get('line_number', ''))
            fixed_paths_lines.add(f"{file_path}:{line_num}")

        remaining_findings = []
        for finding in findings:
            # Determine finding location based on tool
            if finding.get('tool') == 'gitleaks':
                finding_path = finding.get('File', '')
                finding_line = str(finding.get('StartLine', ''))
            elif finding.get('tool') == 'trivy':
                finding_path = finding.get('path', '')
                finding_line = str(finding.get('line', '1'))  # Trivy doesn't have line numbers
            else:  # semgrep
                finding_path = finding.get('path', '')
                finding_line = str(finding.get('start', {}).get('line', ''))

            finding_key = f"{finding_path}:{finding_line}"
            if finding_key not in fixed_paths_lines:
                remaining_findings.append(finding)

        if remaining_findings:
            for finding in remaining_findings[:3]:  # Show first 3
                tool = finding.get('tool', 'unknown')
                if tool == 'gitleaks':
                    message = finding.get('Description', 'Secret detected')
                    file_path = finding.get('File', 'unknown file')
                    line = finding.get('StartLine', '?')
                elif tool == 'trivy':
                    message = finding.get('description', 'Dependency vulnerability')
                    file_path = finding.get('path', 'unknown file')
                    line = finding.get('line', '?')
                else:
                    message = finding.get('extra', {}).get('message', 'Security issue')
                    file_path = finding.get('path', 'unknown file')
                    line = finding.get('start', {}).get('line', '?')

                severity = finding.get('severity', 'unknown')
                severity_label = sanitize_markdown_field(severity, 20).upper() if severity != 'unknown' else 'UNKNOWN'

                # Add cross-file analysis if available
                cross_file_info = ""
                if finding.get('cross_file_summary'):
                    cross_file_info = f" | {sanitize_markdown_field(finding['cross_file_summary'], 200)}"

                safe_message = sanitize_markdown_field(message, 100)
                safe_path = sanitize_markdown_field(file_path, 200)
                safe_line = sanitize_markdown_field(line, 12)
                pr_lines.append(f"**[{severity_label}]** {safe_message} in `{safe_path}:{safe_line}`{cross_file_info}")

            if len(remaining_findings) > 3:
                pr_lines.append(f"... and {len(remaining_findings) - 3} more findings")
        else:
            pr_lines.append("All detected vulnerabilities have been auto-fixed!")

        # Get AI model from environment
        pr_lines.extend([
            "",
            "## Review Required:",
            "- [ ] **Code Review**: Verify fixes are correct and don't break functionality",
            "- [ ] **Testing**: Run tests to ensure no regressions",
            "- [ ] **Manual Fixes**: Address remaining findings that require human review",
            "- [ ] **Security Scan**: Re-run scanner to verify fixes work",
            "",
            "## 🧠 Cross-File Analysis Results",
            self._generate_cross_file_analysis_section(findings),
            "",
            "## Technical Details:",
            f"- **AI Model**: {self.model} with cross-file analysis integration",
            "- **Scanner**: Semgrep, Gitleaks, Trivy + cross-file context analysis",
            f"- **Branch**: `{branch_name}`",
            "",
            "**⚡ Generated by AppSec Galaxy**",
        ])

        return "\n".join(pr_lines)

    def _generate_cross_file_analysis_section(self, findings: list[dict[str, Any]]) -> str:
        """Generate actual cross-file analysis results from enhanced findings"""
        if not findings:
            return "**No findings available for cross-file analysis.**"

        # Calculate basic finding statistics
        total_findings = len(findings)
        critical_findings = len([f for f in findings if f.get('severity', '').lower() == 'critical'])
        high_findings = len([f for f in findings if f.get('severity', '').lower() in ['high', 'error']])

        # Analyze finding types and tools
        tools_used = set()
        file_types = set()
        finding_types = set()

        for finding in findings:
            # Track scanner tools
            tool = finding.get('tool', '')
            if tool:
                tools_used.add(tool)

            # Track file types
            file_path = finding.get('path', finding.get('file', ''))
            if file_path:
                ext = file_path.split('.')[-1].lower() if '.' in file_path else 'unknown'
                file_types.add(ext)

            # Track finding categories
            check_id = finding.get('check_id', finding.get('extra', {}).get('message', ''))
            if 'sql' in check_id.lower():
                finding_types.add('SQL Injection')
            elif 'xss' in check_id.lower() or 'cross-site' in check_id.lower():
                finding_types.add('XSS')
            elif 'password' in check_id.lower() or 'secret' in check_id.lower():
                finding_types.add('Exposed Secrets')
            elif 'path' in check_id.lower() and 'traversal' in check_id.lower():
                finding_types.add('Path Traversal')
            elif 'command' in check_id.lower() or 'injection' in check_id.lower():
                finding_types.add('Command Injection')

        # Try to extract detailed cross-file analysis data if available
        cross_file_results = []
        frameworks_found = set()
        business_impacts = []
        cross_file_chains = []

        for finding in findings:
            # Get cross-file analysis summary if available
            if finding.get('cross_file_summary'):
                cross_file_results.append(finding.get('cross_file_summary'))

            # Extract framework info from various possible locations
            if finding.get('cross_file_analysis', {}).get('context_factors'):
                for factor in finding['cross_file_analysis']['context_factors']:
                    if any(fw in factor.lower() for fw in ['framework', 'express', 'flask', 'django', 'spring', 'react', 'vue']):
                        frameworks_found.add(factor)

            # Extract business impact (path is untrusted: sanitize for Markdown)
            if finding.get('business_impact', {}).get('financial_risk') == 'High':
                safe_path = sanitize_markdown_field(finding.get('path', 'unknown file'), 200)
                business_impacts.append(f"High financial risk in {safe_path}")

            # Extract cross-file analysis. chain_type/severity/description are
            # AI-derived from hostile code: sanitize each before Markdown.
            if finding.get('cross_file_analysis', {}).get('potential_attack_chains'):
                for chain in finding['cross_file_analysis']['potential_attack_chains']:
                    ctype = sanitize_markdown_field(chain.get('chain_type', ''), 80)
                    csev = sanitize_markdown_field(chain.get('severity', ''), 20)
                    cdesc = sanitize_markdown_field(chain.get('description', ''), 200)
                    cross_file_chains.append(f"**{ctype}** ({csev}): {cdesc}")

        # Build analysis sections
        analysis_parts = ["**🧠 Cross-File Security Intelligence:**"]

        # Always show basic statistics
        analysis_parts.append(f"📊 **Scan Coverage**: {total_findings} findings across {len(file_types)} file types using {len(tools_used)} scanners")

        if critical_findings > 0 or high_findings > 0:
            analysis_parts.append(f"🚨 **Risk Level**: {critical_findings} critical, {high_findings} high-severity vulnerabilities")

        if finding_types:
            analysis_parts.append(f"🔍 **Vulnerability Types**: {', '.join(sorted(finding_types)[:5])}")

        # Add detailed cross-file analysis data if available
        if frameworks_found:
            analysis_parts.append(f"🔧 **Framework Detection**: {', '.join(list(frameworks_found)[:3])}")

        if business_impacts:
            unique_impacts = list(set(business_impacts[:3]))
            analysis_parts.append(f"💼 **Business Impact**: {', '.join(unique_impacts)}")

        if cross_file_chains:
            analysis_parts.append(f"🔗 **Cross-file Risks**: {len(cross_file_chains)} attack chains identified")
            for chain in cross_file_chains[:3]:  # Show top 3 chains
                analysis_parts.append(f"   • {chain}")

        if cross_file_results:
            analysis_parts.append(f"🧠 **Cross-File Insights**: {len(cross_file_results)} enhanced findings with contextual analysis")

        return "\n".join(analysis_parts)

    def _generate_dependency_health_section(self, findings: list[dict[str, Any]]) -> str:
        """Generate dependency health context for PR descriptions."""
        try:
            from appsec_galaxy.dependency_analyzer import run_dependency_analysis  # noqa: F401 (availability probe)
            from appsec_galaxy.config import ENABLE_DEPENDENCY_ANALYSIS
            if not ENABLE_DEPENDENCY_ANALYSIS:
                return ""
        except ImportError:
            return ""

        # Check if dependency health data was saved alongside findings
        # Look for enriched Trivy findings with depth/health info
        dep_findings = [f for f in findings if f.get('tool') == 'trivy']
        if not dep_findings:
            return ""

        lines = []
        pkg_names = set()
        for f in dep_findings:
            pkg = f.get('package_name', '') or f.get('extra', {}).get('metadata', {}).get('package_name', '')
            if pkg:
                pkg_names.add(pkg)

        if pkg_names:
            lines.append(f"**{len(pkg_names)} vulnerable packages** detected in dependency scan.")
            lines.append("")
            lines.append("Dependency code-path analysis provides depth and health context.")
            lines.append("Run `analyze_dependency_health` for full details on usage patterns,")
            lines.append("embedding depth, and recommended remediation strategies.")

        return "\n".join(lines)

    def get_default_branch(self, repo_path: str) -> str:
        """Detect the default/main branch (main vs master)."""
        try:
            # Try to get the default branch from git
            result = subprocess.run(
                ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            # Output looks like: "refs/remotes/origin/main" or "refs/remotes/origin/master"
            default_branch = result.stdout.strip().split('/')[-1]
            return default_branch
        except subprocess.CalledProcessError:
            # Fallback: check which branches exist
            try:
                result = subprocess.run(
                    ["git", "branch", "-r"],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    check=True
                )
                branches = result.stdout
                if "origin/main" in branches:
                    return "main"
                elif "origin/master" in branches:
                    return "master"
                else:
                    return "main"  # Default fallback
            except subprocess.CalledProcessError:
                return "main"  # Final fallback

    def create_pull_request(self, repo_path: str, branch_name: str, base_branch: str | None = None, findings: list[dict[str, Any]] | None = None, fixes: list[dict[str, Any]] | None = None) -> str | None:
        """Create a pull request for the fixes (with user confirmation)."""

        # Detect default branch if not provided
        if base_branch is None:
            base_branch = self.get_default_branch(repo_path)

        # User already chose auto-fix, so automatically create PR
        print(f"\n🔄 Security fixes have been committed to branch: {branch_name}")
        print("🚀 Automatically creating Pull Request (user chose auto-fix)...")

        try:
            # Get repo info from git
            result = subprocess.run(
                ["git", "remote", "get-url", "origin"],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True
            )

            remote_url = result.stdout.strip()

            # Extract repo info and create PR (existing logic)
            if "github.com" in remote_url:
                # Handle both SSH and HTTPS URLs
                if remote_url.startswith("git@"):
                    repo_part = remote_url.split(":")[1].replace(".git", "")
                else:
                    repo_part = remote_url.split("github.com/")[1].replace(".git", "")

                owner, repo = repo_part.split("/")

                # Create PR using GitHub CLI (if available)
                # Generate specific title based on findings and fixes
                if findings and fixes:
                    sast_count = len([f for f in findings if f.get('tool') == 'semgrep'])
                    secrets_count = len([f for f in findings if f.get('tool') == 'gitleaks'])

                    if sast_count > 0 and secrets_count > 0:
                        pr_title = f"🔒 Fix {sast_count} SAST + {secrets_count} Secret Vulnerabilities (Need Manual Review)"
                    elif sast_count > 0:
                        # Sanitize vulnerability types to prevent injection
                        fix_types = []
                        for fix in fixes:
                            vuln_type = fix.get('vulnerability_type', '')
                            if vuln_type and validate_vulnerability_type(vuln_type):
                                clean_type = sanitize_git_message(vuln_type.split('.')[-1])
                                if clean_type:
                                    fix_types.append(clean_type)

                        fix_types = list(set(fix_types))  # Remove duplicates
                        if fix_types:
                            top_types = fix_types[:2] if len(fix_types) <= 2 else fix_types[:2] + [f"+{len(fix_types)-2} more"]
                            type_summary = ", ".join(top_types)
                            pr_title = f"🔒 Fix {sast_count} SAST Vulnerabilities ({type_summary})"
                        else:
                            pr_title = f"🔒 Fix {sast_count} SAST Vulnerabilities"
                    elif secrets_count > 0:
                        pr_title = f"🔒 Fix {secrets_count} Secret Vulnerabilities"
                    else:
                        pr_title = f"🔒 Fix {len(fixes)} Security Vulnerabilities"
                else:
                    pr_title = "🔒 AI Security Fixes: Auto-Remediated Vulnerabilities"

                # Generate improved PR body if we have findings data
                if findings and fixes:
                    pr_body = self._generate_improved_pr_body(findings, fixes, branch_name)
                else:
                    # Fallback to basic template
                    pr_body = f"""## 🤖 AI-Generated Security Fixes

This PR contains automatic fixes for security vulnerabilities detected by AppSec Galaxy.

### 🛡️ What was fixed:
- SAST vulnerabilities identified by Semgrep
- Input validation and sanitization improvements
- Code patterns that could lead to security issues

### ⚠️ Review Required:
- [ ] **Code Review**: Verify fixes are correct and don't break functionality
- [ ] **Testing**: Run tests to ensure no regressions
- [ ] **Security Scan**: Re-run scanner to verify fixes work

### 🔍 Technical Details:
- **AI Model**: {self.ai_provider} (`{self.model}`)
- **Scanner**: Semgrep SAST
- **Branch**: `{branch_name}`

**⚡ Generated by AppSec Galaxy**
"""

                # Try to create PR using gh CLI
                try:
                    result = subprocess.run(
                        ["gh", "pr", "create",
                         "--title", pr_title,
                         "--body", pr_body,
                         "--base", base_branch,
                         "--head", branch_name],
                        cwd=repo_path,
                        check=True,
                        capture_output=True,
                        text=True
                    )

                    pr_url = result.stdout.strip()
                    print(f"✅ Pull Request created: {pr_url}")
                    return pr_url

                except subprocess.CalledProcessError as e:
                    # Properly handle different types of stderr
                    error_msg = ""
                    if e.stderr is not None:
                        if isinstance(e.stderr, bytes):
                            error_msg = e.stderr.decode('utf-8', errors='replace')
                        else:
                            error_msg = str(e.stderr)
                    else:
                        error_msg = f"Command failed with exit code {e.returncode}"

                    print("❌ GitHub CLI command failed:")
                    if "not found" in error_msg.lower() or "auth" in error_msg.lower():
                        print("   🔑 GitHub CLI authentication required. Run: gh auth login")
                    else:
                        print(f"   Error: {error_msg}")
                    print(f"📝 Manual PR creation: gh pr create --head {branch_name} --base {base_branch}")
                    return None
                except FileNotFoundError:
                    print("❌ GitHub CLI not found. Install with: brew install gh")
                    print(f"📝 Manual PR creation: gh pr create --head {branch_name} --base {base_branch}")
                    return None
            else:
                print("❌ Not a GitHub repository, PR creation skipped")
                return None

        except Exception as e:
            print(f"❌ Error creating PR: {e}")
            return None

    def remediate_findings(self, sast_findings: list[dict[str, Any]], repo_path: str, all_findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Main method to remediate a list of SAST findings."""
        logger.info(f"🔧 remediate_findings called with {len(sast_findings)} SAST findings")
        # Use all_findings for PR context if provided, otherwise use sast_findings
        if all_findings is None:
            all_findings = sast_findings

        results: dict[str, Any] = {
            'total_findings': len(sast_findings),  # This should be SAST findings for remediation stats
            'remediable_findings': 0,
            'successful_fixes': 0,
            'failed_fixes': 0,
            'skipped_multiline': 0,  # Track vulnerabilities that need multi-line fixes
            'skipped_secrets': 0,  # Track secret detections that need manual review
            'fixes': [],
            'branch_name': None,
            'pr_url': None,
            'success': False,
            'message': ''
        }

        # Track skipped secrets (not auto-fixable)
        secret_findings = []
        for f in sast_findings:
            check_id = f.get('check_id', '').lower()
            secret_patterns = [
                'generic.secrets', 'detected-secret', 'detected-jwt-token',
                'detected-api-key', 'detected-password', 'detected-private-key',
                'hardcoded-password', 'hardcoded-credential'
            ]
            if any(pattern in check_id for pattern in secret_patterns):
                secret_findings.append(f)

        results['skipped_secrets'] = len(secret_findings)

        # Filter remediable findings from SAST findings only
        remediable_findings = [f for f in sast_findings if self.can_remediate(f)]
        results['remediable_findings'] = len(remediable_findings)

        if not remediable_findings:
            logger.info("No remediable findings found")
            results['message'] = "No remediable SAST findings detected"
            return results

        # Create remediation branch
        try:
            branch_name = self.create_remediation_branch(repo_path)
            results['branch_name'] = branch_name
        except Exception as e:
            logger.error(f"Failed to create branch: {e}")
            return results

        # Generate and apply fixes
        successful_fixes = []
        retry_delay = int(os.getenv('APPSEC_AUTO_FIX_DELAY', '0'))  # Default no delay

        for i, finding in enumerate(remediable_findings, 1):
            check_id = finding.get('check_id', 'unknown')
            file_path = finding.get('path', 'unknown')
            logger.info(f"Processing fix {i}/{len(remediable_findings)}: {check_id} in {file_path}")

            # Add delay between fixes to prevent API rate limiting in CI/CD
            if i > 1 and retry_delay > 0:
                import time
                time.sleep(retry_delay)
                logger.debug(f"Rate limiting delay: {retry_delay}s")

            fix = self.generate_code_fix(finding, repo_path)
            if fix:
                logger.info(f"✅ Generated fix for {check_id}")
                if self.apply_fix(fix, repo_path):
                    successful_fixes.append(fix)
                    results['successful_fixes'] += 1
                    logger.info(f"✅ Applied fix {i}: {check_id}")
                else:
                    results['failed_fixes'] += 1
                    logger.error(f"❌ Failed to apply fix {i}: {check_id} in {file_path}")
            else:
                # Fix generation failed - most likely due to multi-line requirement
                # (The _sanitize_model_fix will have logged detailed reason if multi-line)
                results['failed_fixes'] += 1
                # Increment multiline counter (approximate - tracks all fix generation failures)
                results['skipped_multiline'] += 1
                logger.info(f"⏭️  Skipped fix {i}/{len(remediable_findings)}: {check_id} in {file_path}")
                logger.info("    → Reason: Requires multi-line fix or complex refactoring (auto-fix limitation)")
                logger.info("    → Action: This vulnerability will be flagged in the report for manual review")

        results['fixes'] = successful_fixes

        # Commit fixes if any were successful
        if successful_fixes:
            if self.commit_fixes(repo_path, successful_fixes):
                # Push the branch to remote before creating PR
                try:
                    subprocess.run(
                        ["git", "push", "-u", "origin", branch_name],
                        cwd=repo_path,
                        check=True,
                        capture_output=True,
                        text=True
                    )
                    logger.info(f"Pushed branch {branch_name} to remote")
                    print(f"✅ Branch {branch_name} pushed to remote successfully")
                except subprocess.CalledProcessError as e:
                    error_msg = e.stderr or str(e)
                    logger.error(f"Failed to push branch: {error_msg}")
                    print(f"❌ Failed to push branch {branch_name}: {error_msg}")
                    print("   This will prevent PR creation.")
                    results['error'] = f"Failed to push branch: {error_msg}"
                    return results

                # Pass ALL findings to PR creation (use all_findings if provided, fallback to sast_findings)
                pr_findings = all_findings if all_findings is not None else sast_findings
                results['pr_url'] = self.create_pull_request(repo_path, branch_name, None, pr_findings, successful_fixes)
                results['success'] = True
                results['message'] = f"Applied {len(successful_fixes)} SAST fixes"
        else:
            # Clean up unused branch if no fixes were applied
            logger.info(f"No fixes applied, cleaning up branch {branch_name}")
            try:
                subprocess.run(
                    ["git", "checkout", self.get_default_branch(repo_path)],
                    cwd=repo_path,
                    check=True,
                    capture_output=True
                )
                subprocess.run(
                    ["git", "branch", "-D", branch_name],
                    cwd=repo_path,
                    check=True,
                    capture_output=True
                )
                logger.debug(f"Deleted unused branch {branch_name}")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to clean up branch {branch_name}: {e}")
            results['branch_name'] = None
            results['message'] = "No SAST fixes were applied"

        return results

    def can_remediate_dependency(self, finding: dict[str, Any]) -> bool:
        """Check if a dependency vulnerability can be auto-remediated."""
        # Only dependency findings from Trivy can be auto-remediated
        if 'vulnerability_id' not in finding or not finding.get('fixed_version'):
            return False

        # Must have a fixed version available
        fixed_version = finding.get('fixed_version', '').strip()
        if not fixed_version or fixed_version.lower() in ['', 'unknown', 'n/a']:
            return False

        # Check if we support this dependency file type (ONLY TESTED LANGUAGES)
        target_path = finding.get('path', '')
        supported_files = [
            'requirements.txt',  # Python - TESTED ✅
            'package.json',      # Node.js - TESTED ✅
            'package-lock.json', # Node.js lock file (Trivy scans this)
            'yarn.lock',         # Node.js yarn lock file
            'go.mod',           # Go
            'Cargo.toml',       # Rust
            'composer.json',    # PHP
            'pom.xml',          # Java Maven
            'build.gradle',     # Java Gradle
        ]

        return any(supported_file in target_path for supported_file in supported_files)

    def _update_python_requirements(self, file_path: str, pkg_name: str, new_version: str) -> bool:
        """Update a Python requirements.txt file with new package version."""
        try:
            # Validate inputs to prevent injection attacks
            if not validate_package_name(pkg_name):
                logger.error(f"Invalid package name for Python requirements: {pkg_name}")
                return False

            if not validate_version_string(new_version):
                logger.error(f"Invalid version string for Python requirements: {new_version}")
                return False

            if not validate_file_path(file_path):
                logger.error(f"Invalid file path for Python requirements: {file_path}")
                return False

            with open(file_path, encoding='utf-8') as f:
                lines = f.readlines()

            updated = False
            for i, line in enumerate(lines):
                # Match package name at start of line (handle ==, >=, ~=, etc.)
                # Using re.escape() is already safe for the package name
                if re.match(rf'^{re.escape(pkg_name)}\s*[=<>~!]', line.strip()):
                    # Replace with exact version - safe since inputs are validated
                    lines[i] = f"{pkg_name}=={new_version}\n"
                    updated = True
                    logger.debug(f"Updated {pkg_name} to {new_version} in {file_path}")
                    break

            if updated:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.writelines(lines)
                return True
            else:
                logger.debug(f"Package {pkg_name} not found in {file_path}")
                return False

        except Exception as e:
            logger.error(f"Error updating {file_path}: {e}")
            return False

    def _update_nodejs_package_json(self, file_path: str, pkg_name: str, new_version: str, repo_path: str) -> bool:
        """Update a Node.js package.json file with new package version and regenerate lock files."""
        try:
            # Validate inputs to prevent injection attacks
            if not validate_package_name(pkg_name):
                logger.error(f"Invalid package name for Node.js package: {pkg_name}")
                return False

            if not validate_version_string(new_version):
                logger.error(f"Invalid version string for Node.js package: {new_version}")
                return False

            if not validate_file_path(file_path):
                logger.error(f"Invalid file path for Node.js package: {file_path}")
                return False

            with open(file_path, encoding='utf-8') as f:
                package_data = json.load(f)

            updated = False
            # Check dependencies and devDependencies
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies']:
                if dep_type in package_data and pkg_name in package_data[dep_type]:
                    old_version = package_data[dep_type][pkg_name]
                    # Preserve version prefix (^, ~, >=, etc.) if present
                    if old_version.startswith(('^', '~', '>=', '>')):
                        prefix = old_version[0] if old_version[0] in '^~' else '>='
                        package_data[dep_type][pkg_name] = f"{prefix}{new_version}"
                    else:
                        package_data[dep_type][pkg_name] = new_version

                    updated = True
                    logger.debug(f"Updated {pkg_name} to {new_version} in {file_path} ({dep_type})")
                    break

            if updated:
                # Write updated package.json
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(package_data, f, indent=2, ensure_ascii=False)
                    f.write('\n')  # Add newline at end

                # Regenerate lock files if they exist
                package_dir = os.path.dirname(file_path)
                package_lock_path = os.path.join(package_dir, 'package-lock.json')
                yarn_lock_path = os.path.join(package_dir, 'yarn.lock')

                try:
                    if os.path.exists(package_lock_path):
                        logger.debug("Regenerating package-lock.json...")
                        # --ignore-scripts: the scanned repo is untrusted, so
                        # never run its preinstall/postinstall/prepare lifecycle
                        # scripts (arbitrary code execution on the scan host).
                        result = subprocess.run(
                            ["npm", "install", "--package-lock-only", "--ignore-scripts"],
                            cwd=package_dir,
                            capture_output=True,
                            text=True,
                            timeout=120  # 2 minute timeout
                        )
                        if result.returncode == 0:
                            logger.info("✅ package-lock.json updated successfully")
                        else:
                            logger.debug(f"npm install warning: {result.stderr}")

                    elif os.path.exists(yarn_lock_path):
                        logger.info("Regenerating yarn.lock...")
                        # --ignore-scripts: untrusted repo, never run its
                        # lifecycle scripts (see npm branch above).
                        result = subprocess.run(
                            ["yarn", "install", "--no-progress", "--ignore-scripts"],
                            cwd=package_dir,
                            capture_output=True,
                            text=True,
                            timeout=120  # 2 minute timeout
                        )
                        if result.returncode == 0:
                            logger.info("✅ yarn.lock updated successfully")
                        else:
                            logger.warning(f"yarn install warning: {result.stderr}")

                except subprocess.TimeoutExpired:
                    logger.warning("Lock file regeneration timed out (but package.json was updated)")
                except FileNotFoundError as e:
                    logger.warning(f"Package manager not found ({e}), but package.json was updated")
                except Exception as e:
                    logger.warning(f"Lock file regeneration failed ({e}), but package.json was updated")

                return True
            else:
                logger.debug(f"Package {pkg_name} not found in {file_path}")
                return False

        except Exception as e:
            logger.error(f"Error updating {file_path}: {e}")
            return False

    def _fix_dependency(self, finding: dict[str, Any], repo_path: str) -> dict[str, Any] | None:
        """Fix a single dependency vulnerability with bulletproof error handling."""
        backup_path = None
        try:
            target_path = finding.get('path', '')
            pkg_name = finding.get('pkg_name', '')
            current_version = finding.get('installed_version', '')
            fixed_version = finding.get('fixed_version', '')
            vuln_id = finding.get('vulnerability_id', '')

            full_path = os.path.join(repo_path, target_path)
            if not os.path.exists(full_path):
                logger.warning(f"Dependency file not found: {full_path}")
                return None

            # Create backup before making changes
            backup_path = f"{full_path}.backup"
            with open(full_path, encoding='utf-8') as source:
                with open(backup_path, 'w', encoding='utf-8') as backup:
                    backup.write(source.read())
            logger.debug(f"Created backup: {backup_path}")

            # Handle dependency files
            success = False
            if 'requirements.txt' in target_path:
                success = self._update_python_requirements(full_path, pkg_name, fixed_version)
            elif 'package.json' in target_path:
                success = self._update_nodejs_package_json(full_path, pkg_name, fixed_version, repo_path)
            elif 'package-lock.json' in target_path or 'yarn.lock' in target_path:
                # Map lock files to package.json for Node.js dependency fixes
                package_json_path = os.path.join(repo_path, 'package.json')
                if os.path.exists(package_json_path):
                    success = self._update_nodejs_package_json(package_json_path, pkg_name, fixed_version, repo_path)
                else:
                    logger.warning(f"package.json not found for lock file: {target_path}")
                    success = False
            elif 'go.mod' in target_path:
                success = self._update_go_mod(target_path, pkg_name, fixed_version, repo_path)
            elif 'Cargo.toml' in target_path:
                success = self._update_rust_cargo(full_path, pkg_name, fixed_version)
            elif 'composer.json' in target_path:
                success = self._update_php_composer(full_path, pkg_name, fixed_version)
            elif 'pom.xml' in target_path:
                success = self._update_java_maven(full_path, pkg_name, fixed_version)
            elif 'build.gradle' in target_path:
                success = self._update_java_gradle(full_path, pkg_name, fixed_version)
            else:
                # Only log unsupported file types once to reduce noise
                file_type = os.path.basename(target_path)
                if file_type not in self._logged_unsupported_types:
                    logger.info(f"Dependency file type not yet supported: {file_type}")
                    self._logged_unsupported_types.add(file_type)

                # Clean up backup for unsupported files
                if backup_path and os.path.exists(backup_path):
                    os.remove(backup_path)
                return None

            if success:
                # Clean up backup on success
                if backup_path and os.path.exists(backup_path):
                    os.remove(backup_path)

                return {
                    'file_path': target_path,
                    'package_name': pkg_name,
                    'old_version': current_version,
                    'new_version': fixed_version,
                    'vulnerability_id': vuln_id,
                    'description': f"Updated {pkg_name} from {current_version} to {fixed_version}"
                }
            else:
                # Restore from backup on failure
                if backup_path and os.path.exists(backup_path):
                    logger.debug(f"Restoring {target_path} from backup due to update failure")
                    with open(backup_path, encoding='utf-8') as backup:
                        with open(full_path, 'w', encoding='utf-8') as target:
                            target.write(backup.read())
                    os.remove(backup_path)
                return None

        except Exception as e:
            logger.error(f"Error fixing dependency: {e}")
            # Restore from backup on exception
            if backup_path and os.path.exists(backup_path):
                try:
                    logger.debug(f"Restoring {target_path} from backup due to exception")
                    with open(backup_path, encoding='utf-8') as backup:
                        with open(full_path, 'w', encoding='utf-8') as target:
                            target.write(backup.read())
                    os.remove(backup_path)
                except Exception as restore_error:
                    logger.error(f"Failed to restore backup: {restore_error}")
            return None

    def create_dependency_branch(self, repo_path: str, base_branch: str = "main") -> str:
        """Create a new branch for dependency fixes."""
        try:
            # Detect actual default branch
            detected_branch = self.get_default_branch(repo_path)
            if detected_branch:
                base_branch = detected_branch

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            branch_name = f"security-fixes-deps-{timestamp}"

            # Switch to base branch first to ensure clean start
            subprocess.run(
                ["git", "checkout", base_branch],
                cwd=repo_path,
                check=True,
                capture_output=True
            )

            # Create and checkout new branch from clean base
            subprocess.run(
                ["git", "checkout", "-b", branch_name],
                cwd=repo_path,
                check=True,
                capture_output=True
            )

            logger.info(f"Created dependency remediation branch: {branch_name}")
            return branch_name

        except subprocess.CalledProcessError as e:
            logger.error(f"Error creating dependency branch: {e}")
            raise

    def commit_dependency_fixes(self, repo_path: str, fixes: list[dict[str, Any]]) -> bool:
        """Commit dependency fixes."""
        try:
            subprocess.run(
                ["git", "add", "."],
                cwd=repo_path,
                check=True,
                capture_output=True
            )

            fix_count = len(fixes)
            commit_message = f"🔒 Auto-upgrade {fix_count} vulnerable dependencies\n\n"

            # Only show first 5 packages to keep commit message manageable
            if fix_count > 5:
                commit_message += f"Key packages updated (showing 5 of {fix_count}):\n"
                for fix in fixes[:5]:
                    # Sanitize package names and versions to prevent injection
                    pkg = sanitize_git_message(str(fix.get('package_name', 'Unknown')))
                    new_ver = sanitize_git_message(str(fix.get('new_version', 'Unknown')))
                    if pkg and new_ver:  # Only add if sanitization didn't remove everything
                        commit_message += f"- {pkg} → {new_ver}\n"
                commit_message += f"... and {fix_count - 5} more packages\n"
            else:
                commit_message += "Updated packages:\n"
                for fix in fixes:
                    # Sanitize package names and versions to prevent injection
                    pkg = sanitize_git_message(str(fix.get('package_name', 'Unknown')))
                    new_ver = sanitize_git_message(str(fix.get('new_version', 'Unknown')))
                    if pkg and new_ver:  # Only add if sanitization didn't remove everything
                        commit_message += f"- {pkg} → {new_ver}\n"

            # Use a simpler single-line commit message to avoid git issues
            simple_message = f"🔒 Auto-upgrade {fix_count} vulnerable dependencies"
            subprocess.run(
                ["git", "commit", "-m", simple_message],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True
            )

            logger.info(f"Committed {fix_count} dependency fixes")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Error committing dependency fixes: {e}")
            if hasattr(e, 'stderr') and e.stderr:
                logger.error(f"Git error details: {e.stderr}")
            if hasattr(e, 'stdout') and e.stdout:
                logger.error(f"Git output: {e.stdout}")
            return False

    def remediate_dependencies(self, dependency_findings: list[dict[str, Any]], repo_path: str) -> dict[str, Any]:
        """Main method to remediate dependency vulnerabilities."""
        logger.info(f"🔧 remediate_dependencies called with {len(dependency_findings)} dependency findings")
        results: dict[str, Any] = {
            'total_findings': len(dependency_findings),
            'remediable_findings': 0,
            'successful_fixes': 0,
            'failed_fixes': 0,
            'fixes': [],
            'branch_name': None,
            'pr_url': None,
            'success': False,
            'message': ''
        }

        # Filter remediable dependency findings
        remediable_findings = [f for f in dependency_findings if self.can_remediate_dependency(f)]
        results['remediable_findings'] = len(remediable_findings)

        if not remediable_findings:
            logger.info("No remediable dependency findings found")
            results['message'] = "No dependencies with available fixes"
            return results

        # Create dependency remediation branch
        try:
            branch_name = self.create_dependency_branch(repo_path)
            results['branch_name'] = branch_name
        except Exception as e:
            logger.error(f"Failed to create dependency branch: {e}")
            return results

        # Apply dependency fixes
        successful_fixes = []

        for finding in remediable_findings:
            fix = self._fix_dependency(finding, repo_path)
            if fix:
                successful_fixes.append(fix)
                results['successful_fixes'] += 1
            else:
                results['failed_fixes'] += 1

        results['fixes'] = successful_fixes
        results['successful_fixes'] = len(successful_fixes)  # Add count for display

        # Show summary of what was accomplished
        if successful_fixes:
            logger.info(f"📦 Updated {len(successful_fixes)} vulnerable dependencies")

        # Show summary of unsupported file types (less noisy)
        if self._logged_unsupported_types:
            skipped_types = ', '.join(sorted(self._logged_unsupported_types))
            logger.debug(f"Skipped unsupported file types: {skipped_types}")

        # Commit fixes if any were successful
        if successful_fixes:
            if self.commit_dependency_fixes(repo_path, successful_fixes):
                # Push branch and create PR
                try:
                    subprocess.run(
                        ["git", "push", "-u", "origin", branch_name],
                        cwd=repo_path,
                        check=True,
                        capture_output=True,
                        text=True
                    )
                    logger.info(f"Pushed dependency branch {branch_name} to remote")
                    print(f"✅ Dependency branch {branch_name} pushed to remote successfully")

                    # Create PR for dependency fixes
                    results['pr_url'] = self._create_dependency_pr(repo_path, branch_name, dependency_findings, successful_fixes)
                    results['success'] = True
                    results['message'] = f"Updated {len(successful_fixes)} vulnerable dependencies"
                except subprocess.CalledProcessError as e:
                    error_msg = e.stderr or str(e)
                    logger.error(f"Failed to push dependency branch: {error_msg}")
                    print(f"❌ Failed to push dependency branch {branch_name}: {error_msg}")
                    print("   This will prevent PR creation.")
                    results['error'] = f"Failed to push branch: {error_msg}"
        else:
            results['message'] = "No dependency fixes were applied"

        return results

    def _create_dependency_pr(self, repo_path: str, branch_name: str, findings: list[dict[str, Any]], fixes: list[dict[str, Any]]) -> str | None:
        """Create a pull request specifically for dependency fixes."""
        try:
            base_branch = self.get_default_branch(repo_path)

            # Generate smarter title based on actual vulnerabilities and cross-file analysis
            if fixes:
                # Get severity breakdown from findings
                critical_count = len([f for f in findings if f.get('Severity', '').upper() == 'CRITICAL'])
                high_count = len([f for f in findings if f.get('Severity', '').upper() == 'HIGH'])

                # Get unique package names (avoiding duplicates) - sanitize for safety
                raw_packages = []
                for fix in fixes[:3]:
                    pkg_name = fix.get('package_name', '')
                    if validate_package_name(pkg_name):
                        clean_pkg = sanitize_git_message(pkg_name)
                        if clean_pkg:
                            raw_packages.append(clean_pkg)

                unique_packages = list(dict.fromkeys(raw_packages))
                remaining = len(fixes) - len(unique_packages)

                # Create severity-aware title
                severity_text = ""
                if critical_count > 0:
                    severity_text = f" ({critical_count} Critical"
                    if high_count > 0:
                        severity_text += f", {high_count} High)"
                    else:
                        severity_text += ")"
                elif high_count > 0:
                    severity_text = f" ({high_count} High Risk)"

                # Create package summary avoiding duplicates
                if unique_packages:
                    if remaining > 0:
                        pkg_summary = f"{', '.join(unique_packages)} +{remaining} more"
                    else:
                        pkg_summary = ', '.join(unique_packages)

                    pr_title = f"📦 Upgrade {len(fixes)} Vulnerable Dependencies{severity_text} - {pkg_summary}"
                else:
                    pr_title = f"📦 Upgrade {len(fixes)} Vulnerable Dependencies{severity_text}"
            else:
                pr_title = "📦 Security: Auto-upgrade vulnerable dependencies"

            # Build dependency-focused PR body
            total_findings = len(findings)
            fixes_applied = len(fixes)

            pr_lines = [
                "# Dependency Security Updates",
                "",
                "## Summary",
                f"* {total_findings} vulnerable dependencies detected",
                f"* {fixes_applied} packages automatically upgraded to secure versions",
                "",
                "## Package Updates",
            ]

            # Package names, versions, and CVE ids come from the scanned
            # repo's manifests and Trivy output: sanitize before Markdown.
            for fix in fixes:
                pkg = sanitize_markdown_field(fix['package_name'], 120)
                old_ver = sanitize_markdown_field(fix['old_version'], 40)
                new_ver = sanitize_markdown_field(fix['new_version'], 40)
                vuln_id = sanitize_markdown_field(fix.get('vulnerability_id', ''), 40)
                pr_lines.append(f"* **{pkg}**: `{old_ver}` → `{new_ver}` (fixes {vuln_id})")

            # Add dependency health context if available
            dep_health_lines = self._generate_dependency_health_section(findings)

            pr_lines.extend([
                "",
                "## 🧠 Cross-File Dependency Analysis",
                self._generate_cross_file_analysis_section(findings),
            ])
            if dep_health_lines:
                pr_lines.extend(["", "## 📦 Dependency Health Context", dep_health_lines])
            pr_lines.extend([
                "",
                "## Review Checklist",
                "- [ ] **Compatibility**: Verify version upgrades don't break functionality",
                "- [ ] **Testing**: Run full test suite to ensure no regressions",
                "- [ ] **Dependencies**: Check for any indirect dependency conflicts",
                "",
                "**⚡ Generated by AppSec Galaxy**",
            ])

            pr_body = "\n".join(pr_lines)

            # Create PR using GitHub CLI
            result = subprocess.run(
                ["gh", "pr", "create",
                 "--title", pr_title,
                 "--body", pr_body,
                 "--base", base_branch,
                 "--head", branch_name],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True
            )

            pr_url = result.stdout.strip()
            print(f"✅ Dependency PR created: {pr_url}")
            return pr_url

        except Exception as e:
            logger.error(f"Error creating dependency PR: {e}")
            return None

    def _update_go_mod(self, file_path: str, pkg_name: str, new_version: str, repo_path: str) -> bool:
        """Update Go go.mod file with new package version."""
        try:
            # Validate inputs to prevent command injection
            if not validate_package_name(pkg_name):
                logger.error(f"Invalid package name for Go module: {pkg_name}")
                return False

            if not validate_version_string(new_version):
                logger.error(f"Invalid version string for Go module: {new_version}")
                return False

            if not validate_file_path(file_path):
                logger.error(f"Invalid file path for Go module: {file_path}")
                return False

            go_mod_dir = os.path.dirname(os.path.join(repo_path, file_path))

            # Use separate arguments to prevent injection - never use f-strings in subprocess
            cmd = ["go", "get", f"{pkg_name}@v{new_version}"]

            # Log the command for debugging (safe since inputs are validated)
            logger.debug(f"Running Go command: {' '.join(shlex.quote(arg) for arg in cmd)}")

            # GOTOOLCHAIN=local: the scanned repo is untrusted; refuse to
            # download and execute a different Go toolchain named in its
            # go.mod (Go 1.21+ toolchain switching is a code-execution vector).
            go_env = os.environ.copy()
            go_env['GOTOOLCHAIN'] = 'local'
            result = subprocess.run(
                cmd, cwd=go_mod_dir, capture_output=True, text=True, timeout=60,
                shell=False, env=go_env
            )

            if result.returncode == 0:
                logger.debug(f"Updated Go module {pkg_name} to v{new_version}")
                return True
            else:
                logger.warning(f"Go get failed for {pkg_name}: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Error updating Go module {pkg_name}: {e}")
            return False

    def _update_rust_cargo(self, file_path: str, pkg_name: str, new_version: str) -> bool:
        """Update Rust Cargo.toml file with new package version."""
        try:
            # Validate inputs to prevent injection attacks
            if not validate_package_name(pkg_name):
                logger.error(f"Invalid package name for Rust crate: {pkg_name}")
                return False

            if not validate_version_string(new_version):
                logger.error(f"Invalid version string for Rust crate: {new_version}")
                return False

            if not validate_file_path(file_path):
                logger.error(f"Invalid file path for Rust Cargo.toml: {file_path}")
                return False

            with open(file_path, encoding='utf-8') as f:
                content = f.read()

            lines = content.split('\n')
            updated = False
            in_dependencies = False

            for i, line in enumerate(lines):
                if line.strip().startswith('[') and 'dependencies' in line:
                    in_dependencies = True
                    continue
                elif line.strip().startswith('[') and 'dependencies' not in line:
                    in_dependencies = False
                    continue

                if in_dependencies and pkg_name in line and '=' in line:
                    if f'{pkg_name} =' in line:
                        if '{' in line:  # Complex dependency
                            pattern = r'version\s*=\s*"[^"]*"'
                            lines[i] = re.sub(pattern, f'version = "{new_version}"', line)
                        else:  # Simple version
                            lines[i] = re.sub(r'"[^"]*"', f'"{new_version}"', line)

                        updated = True
                        logger.debug(f"Updated {pkg_name} to {new_version} in {file_path}")
                        break

            if updated:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(lines))
                return True
            else:
                logger.debug(f"Package {pkg_name} not found in {file_path}")
                return False

        except Exception as e:
            logger.error(f"Error updating {file_path}: {e}")
            return False

    def _update_php_composer(self, file_path: str, pkg_name: str, new_version: str) -> bool:
        """Update PHP composer.json file with new package version."""
        try:
            # Validate inputs to prevent injection attacks
            if not validate_package_name(pkg_name):
                logger.error(f"Invalid package name for PHP composer: {pkg_name}")
                return False

            if not validate_version_string(new_version):
                logger.error(f"Invalid version string for PHP composer: {new_version}")
                return False

            if not validate_file_path(file_path):
                logger.error(f"Invalid file path for PHP composer.json: {file_path}")
                return False

            with open(file_path, encoding='utf-8') as f:
                composer_data = json.load(f)

            updated = False
            for dep_type in ['require', 'require-dev']:
                if dep_type in composer_data and pkg_name in composer_data[dep_type]:
                    old_version = composer_data[dep_type][pkg_name]

                    # Preserve version operators
                    if old_version.startswith(('^', '~', '>=', '>')):
                        operator = old_version[0] if old_version[0] in '^~' else '>='
                        composer_data[dep_type][pkg_name] = f"{operator}{new_version}"
                    else:
                        composer_data[dep_type][pkg_name] = new_version

                    updated = True
                    logger.debug(f"Updated {pkg_name} to {new_version} in {file_path}")
                    break

            if updated:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(composer_data, f, indent=4)
                    f.write('\n')
                return True
            else:
                logger.debug(f"Package {pkg_name} not found in {file_path}")
                return False

        except Exception as e:
            logger.error(f"Error updating {file_path}: {e}")
            return False

    def _update_java_maven(self, file_path: str, pkg_name: str, new_version: str) -> bool:
        """Update Java Maven pom.xml file with new package version."""
        try:
            # Validate inputs to prevent injection attacks
            if not validate_package_name(pkg_name):
                logger.error(f"Invalid package name for Java Maven: {pkg_name}")
                return False

            if not validate_version_string(new_version):
                logger.error(f"Invalid version string for Java Maven: {new_version}")
                return False

            if not validate_file_path(file_path):
                logger.error(f"Invalid file path for Java Maven pom.xml: {file_path}")
                return False

            # XXE defense: scanned repos are untrusted; use defusedxml.
            import defusedxml.ElementTree as ET

            tree = ET.parse(file_path)
            root = tree.getroot()

            # Handle namespace
            namespace = ''
            if root.tag.startswith('{'):
                namespace = root.tag[root.tag.find('{')+1:root.tag.find('}')]
                ns_map = {'maven': namespace}
                ns_prefix = 'maven:'
            else:
                ns_map = {}
                ns_prefix = ''

            updated = False
            dependencies = root.findall(f".//{ns_prefix}dependencies/{ns_prefix}dependency", ns_map)

            for dep in dependencies:
                group_elem = dep.find(f"{ns_prefix}groupId", ns_map)
                artifact_elem = dep.find(f"{ns_prefix}artifactId", ns_map)
                version_elem = dep.find(f"{ns_prefix}version", ns_map)

                if group_elem is not None and artifact_elem is not None:
                    maven_name = f"{group_elem.text}:{artifact_elem.text}"
                    if maven_name == pkg_name and version_elem is not None:
                        version_elem.text = new_version
                        updated = True
                        logger.debug(f"Updated {pkg_name} to {new_version} in {file_path}")
                        break

            if updated:
                tree.write(file_path, encoding='utf-8', xml_declaration=True)
                return True
            else:
                logger.debug(f"Package {pkg_name} not found in {file_path}")
                return False

        except Exception as e:
            logger.error(f"Error updating {file_path}: {e}")
            return False

    def _update_java_gradle(self, file_path: str, pkg_name: str, new_version: str) -> bool:
        """Update Java Gradle build.gradle file with new package version."""
        try:
            # Validate inputs to prevent injection attacks
            if not validate_package_name(pkg_name):
                logger.error(f"Invalid package name for Java Gradle: {pkg_name}")
                return False

            if not validate_version_string(new_version):
                logger.error(f"Invalid version string for Java Gradle: {new_version}")
                return False

            if not validate_file_path(file_path):
                logger.error(f"Invalid file path for Java Gradle build.gradle: {file_path}")
                return False

            with open(file_path, encoding='utf-8') as f:
                content = f.read()

            lines = content.split('\n')
            updated = False

            for i, line in enumerate(lines):
                if line.strip().startswith('//'):
                    continue

                if pkg_name in line and any(dep in line for dep in
                    ['implementation', 'compile', 'api', 'testImplementation']):

                    for quote in ["'", '"']:
                        if f'{quote}{pkg_name}:' in line:
                            # Find version part and replace
                            start = line.find(f'{quote}{pkg_name}:')
                            if start != -1:
                                version_start = line.find(':', start + len(f'{quote}{pkg_name}:'))
                                end_quote = line.find(quote, version_start)

                                if version_start != -1 and end_quote != -1:
                                    lines[i] = (line[:version_start+1] + new_version + line[end_quote:])
                                    updated = True
                                    logger.debug(f"Updated {pkg_name} to {new_version} in {file_path}")
                                    break

                    if updated:
                        break

            if updated:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(lines))
                return True
            else:
                logger.debug(f"Package {pkg_name} not found in {file_path}")
                return False

        except Exception as e:
            logger.error(f"Error updating {file_path}: {e}")
            return False


# Convenience wrapper function for main.py integration
def create_remediation_pr(repo_path: str, findings: list[dict[str, Any]], fix_type: str) -> bool:
    """
    Wrapper function to create auto-remediation PRs for SAST or dependency findings.

    Args:
        repo_path: Path to the repository
        findings: List of vulnerability findings
        fix_type: 'sast' or 'dependencies'
    """
    try:
        # NOTE: per-customer GitHub PAT injection is a planned refactor when
        # this becomes a multi-tenant sidecar; today we still read GITHUB_TOKEN
        # from process env (single-operator assumption).
        from appsec_galaxy.scanners.ai_scanner import _get_ai_provider

        ai_provider = _get_ai_provider()

        # Create remediator instance
        configured_model = os.getenv('AI_MODEL', '').strip() or None
        remediator = AutoRemediator(ai_provider, model=configured_model)

        if fix_type == 'sast':
            semgrep_count = len([f for f in findings if f.get('tool') == 'semgrep'])
            gitleaks_count = len([f for f in findings if f.get('tool') == 'gitleaks'])
            print(f"🔧 Processing {semgrep_count} SAST code issues + {gitleaks_count} secrets...")
            result = remediator.remediate_findings(findings, repo_path)

            if result.get('success'):
                print("✅ SAST auto-remediation completed!")
                print(f"   • Fixes applied: {result.get('successful_fixes', 0)}")

                # Show skip summary if vulnerabilities were skipped
                skipped_multiline = result.get('skipped_multiline', 0)
                skipped_secrets = result.get('skipped_secrets', 0)

                if skipped_multiline > 0:
                    print(f"   • Skipped (multi-line fix required): {skipped_multiline}")
                    print("     → These vulnerabilities require complex refactoring (expected for SQL injection, etc.)")
                    print("     → See report for detailed recommendations")

                if skipped_secrets > 0:
                    print(f"   • Skipped (secrets - manual review): {skipped_secrets}")
                    print("     → Remove hardcoded secrets and use environment variables")

                if result.get('pr_url'):
                    print(f"   • PR created: {result['pr_url']}")
            else:
                message = result.get('error') or result.get('message') or 'No remediations were applied'
                print(f"⚠️  SAST auto-remediation had issues: {message}")

                # Still show what was skipped even if no fixes were applied
                skipped_multiline = result.get('skipped_multiline', 0)
                skipped_secrets = result.get('skipped_secrets', 0)

                if skipped_multiline > 0 or skipped_secrets > 0:
                    print("\n📋 Vulnerabilities requiring manual review:")
                    if skipped_secrets > 0:
                        print(f"   • {skipped_secrets} secrets detection(s) - remove hardcoded credentials")
                    if skipped_multiline > 0:
                        print(f"   • {skipped_multiline} complex vulnerability(ies) - require multi-line fixes")
                        print("     → This is expected behavior for vulnerabilities like SQL injection refactoring")
                        print("     → The report contains AI-generated fix recommendations for manual implementation")

        elif fix_type == 'dependencies':
            print(f"🔧 Processing {len(findings)} dependency findings...")
            result = remediator.remediate_dependencies(findings, repo_path)

            if result.get('success'):
                print("✅ Dependency auto-remediation completed!")
                print(f"   • Fixes applied: {result.get('successful_fixes', 0)}")
                if result.get('pr_url'):
                    print(f"   • PR created: {result['pr_url']}")
            else:
                message = result.get('error') or result.get('message') or 'No dependency remediations were applied'
                print(f"⚠️  Dependency auto-remediation had issues: {message}")
        else:
            print(f"❌ Unknown fix type: {fix_type}")
            return False

    except Exception as e:
        logger.error(f"Auto-remediation failed: {e}")
        print(f"❌ Auto-remediation failed: {e}")
        return False

    return True
