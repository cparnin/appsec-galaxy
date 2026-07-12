"""
Shared validation utilities for security scanner modules.

This module provides common validation functions used across all scanner modules
to prevent code duplication and ensure consistent security practices.
"""

import os
from pathlib import Path
from appsec_galaxy.exceptions import ValidationError, BinaryNotFoundError
from appsec_galaxy.logging_config import get_logger

logger = get_logger(__name__)

def validate_binary_path(env_var: str, default_bin: str, raise_on_error: bool = False) -> str | None:
    """
    Securely validate binary path from environment variable.

    Args:
        env_var: Environment variable name
        default_bin: Default binary name
        raise_on_error: If True, raise exceptions instead of returning None

    Returns:
        str: Validated binary path or None if invalid (when raise_on_error=False)

    Raises:
        BinaryNotFoundError: When binary validation fails (when raise_on_error=True)
    """
    try:
        bin_path = os.getenv(env_var, default_bin)

        # Basic validation
        if not bin_path or not isinstance(bin_path, str):
            error_msg = f"Invalid binary path from {env_var}"
            logger.error(error_msg)
            if raise_on_error:
                raise BinaryNotFoundError(error_msg, scanner=default_bin)
            return None

        # Check for dangerous characters
        dangerous_chars = [';', '|', '&', '$', '`', '$(', '${', '\n', '\r']
        if any(char in bin_path for char in dangerous_chars):
            error_msg = f"Potentially dangerous characters in binary path: {env_var}"
            logger.error(error_msg)
            if raise_on_error:
                raise BinaryNotFoundError(error_msg, scanner=default_bin)
            return None

        # Remove null bytes
        clean_path = bin_path.replace('\x00', '')
        if clean_path != bin_path:
            error_msg = f"Invalid characters in binary path: {env_var}"
            logger.error(error_msg)
            if raise_on_error:
                raise BinaryNotFoundError(error_msg, scanner=default_bin)
            return None

        return clean_path

    except BinaryNotFoundError:
        raise  # Re-raise our custom exception
    except Exception as e:
        error_msg = f"Error validating binary path {env_var}: {e}"
        logger.error(error_msg)
        if raise_on_error:
            raise BinaryNotFoundError(error_msg, scanner=default_bin) from e
        return None

def validate_repo_path(repo_path: str, raise_on_error: bool = False) -> Path | None:
    """
    Securely validate repository path to prevent command injection and path traversal.

    Args:
        repo_path: User-provided repository path
        raise_on_error: If True, raise exceptions instead of returning None

    Returns:
        Path: Validated Path object or None if invalid (when raise_on_error=False)

    Raises:
        ValidationError: When path validation fails (when raise_on_error=True)
    """
    try:
        # Input sanitization
        if not repo_path or not isinstance(repo_path, str):
            error_msg = "Repository path must be a non-empty string"
            logger.error(error_msg)
            if raise_on_error:
                raise ValidationError(error_msg, details={'path': repo_path})
            return None

        # Remove null bytes and other dangerous characters
        clean_path = repo_path.replace('\x00', '')
        if clean_path != repo_path:
            error_msg = "Invalid characters in repository path"
            logger.error(error_msg)
            if raise_on_error:
                raise ValidationError(error_msg, details={'path': repo_path})
            return None

        # Check for suspicious patterns
        dangerous_patterns = [';', '|', '&', '$', '`', '$(', '${']
        if any(pattern in clean_path for pattern in dangerous_patterns):
            error_msg = "Potentially dangerous characters in repository path"
            logger.error(error_msg)
            if raise_on_error:
                raise ValidationError(error_msg, details={'path': repo_path, 'dangerous_patterns': dangerous_patterns})
            return None

        # Convert to Path and resolve
        path = Path(clean_path).resolve()

        # Additional security checks
        if not path.exists():
            error_msg = f"Repository path does not exist: {path}"
            logger.error(error_msg)
            if raise_on_error:
                raise ValidationError(error_msg, details={'path': str(path)})
            return None

        if not path.is_dir():
            error_msg = f"Repository path is not a directory: {path}"
            logger.error(error_msg)
            if raise_on_error:
                raise ValidationError(error_msg, details={'path': str(path)})
            return None

        # Check path length
        if len(str(path)) > 4096:
            error_msg = "Repository path too long"
            logger.error(error_msg)
            if raise_on_error:
                raise ValidationError(error_msg, details={'path': str(path), 'length': len(str(path))})
            return None

        return path

    except ValidationError:
        raise  # Re-raise our custom exception
    except Exception as e:
        error_msg = f"Error validating repository path: {e}"
        logger.error(error_msg)
        if raise_on_error:
            raise ValidationError(error_msg, details={'path': repo_path, 'original_error': str(e)}) from e
        return None

def detect_languages(repo_path: Path) -> set:
    """
    Detect programming languages in a repository by scanning file extensions.

    This mimics how Semgrep auto-detects languages - by file extension matching.
    Used to determine which code quality linters should be run.

    Args:
        repo_path: Path to repository to analyze

    Returns:
        set: Set of language identifiers (e.g., {'javascript', 'python', 'java'})
    """
    # Comprehensive language mapping based on file extensions
    language_map = {
        # JavaScript/TypeScript ecosystem
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.mjs': 'javascript',
        '.cjs': 'javascript',

        # Python
        '.py': 'python',
        '.pyw': 'python',
        '.pyi': 'python',

        # Java/JVM
        '.java': 'java',
        '.kt': 'kotlin',
        '.kts': 'kotlin',
        '.groovy': 'groovy',
        '.scala': 'scala',

        # C/C++/C#
        '.c': 'c',
        '.h': 'c',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.cxx': 'cpp',
        '.hpp': 'cpp',
        '.cs': 'csharp',

        # Go
        '.go': 'go',

        # Rust
        '.rs': 'rust',

        # Ruby
        '.rb': 'ruby',
        '.erb': 'ruby',

        # PHP
        '.php': 'php',
        '.phtml': 'php',

        # Swift
        '.swift': 'swift',

        # Other languages
        '.sh': 'shell',
        '.bash': 'shell',
        '.zsh': 'shell',
        '.r': 'r',
        '.R': 'r',
    }

    detected_languages = set()
    files_checked = 0
    max_files_to_check = 10000  # Prevent runaway scanning on huge repos

    try:
        # Scan repository for file extensions
        for file_path in repo_path.rglob('*'):
            # Stop if we've checked too many files
            if files_checked >= max_files_to_check:
                logger.warning(f"Reached max file check limit ({max_files_to_check}), stopping language detection")
                break

            # Skip directories and common ignore patterns
            if file_path.is_dir():
                continue

            # Skip common ignored directories
            path_parts = file_path.parts
            ignored_dirs = {
                'node_modules', '.git', '__pycache__', '.venv', 'venv',
                'dist', 'build', '.cache', 'target', 'vendor', '.idea',
                '.vscode', 'coverage', '.pytest_cache', 'outputs'
            }
            if any(ignored in path_parts for ignored in ignored_dirs):
                continue

            files_checked += 1

            # Check file extension
            file_extension = file_path.suffix.lower()
            if file_extension in language_map:
                language = language_map[file_extension]
                detected_languages.add(language)

                # Early exit optimization: if we found the most common languages, we can stop
                # This speeds up detection on large repos
                if len(detected_languages) >= 5 and files_checked > 1000:
                    logger.debug(f"Found {len(detected_languages)} languages after checking {files_checked} files, stopping early")
                    break

        logger.info(f"🔍 Language detection: Found {len(detected_languages)} languages in {files_checked} files")
        logger.debug(f"Detected languages: {', '.join(sorted(detected_languages))}")

        return detected_languages

    except Exception as e:
        logger.warning(f"Language detection failed: {e}")
        # Return empty set on failure - scanners will still run security scans
        return set()

def filter_code_quality_by_severity(findings: list, min_severity: str | None = None) -> list:
    """
    Filter code quality findings by minimum severity level to reduce noise.

    Severity hierarchy: critical > high > medium > low

    Args:
        findings: List of findings (dicts with 'category' and 'severity' keys)
        min_severity: Minimum severity to include ('critical', 'high', 'medium', 'low', 'all')
                     If None, reads from CODE_QUALITY_MIN_SEVERITY config

    Returns:
        list: Filtered findings (code quality findings filtered by severity, security findings untouched)

    Example:
        >>> findings = [
        ...     {'category': 'code_quality', 'severity': 'low', 'message': 'Style issue'},
        ...     {'category': 'code_quality', 'severity': 'high', 'message': 'Bug risk'},
        ...     {'category': 'security', 'severity': 'low', 'message': 'XSS'}
        ... ]
        >>> filter_code_quality_by_severity(findings, 'high')
        [{'category': 'code_quality', 'severity': 'high', ...}, {'category': 'security', 'severity': 'low', ...}]
    """
    if not findings:
        return []

    # Get minimum severity from config if not provided
    if min_severity is None:
        from appsec_galaxy.config import CODE_QUALITY_MIN_SEVERITY
        min_severity = CODE_QUALITY_MIN_SEVERITY

    min_severity = min_severity.lower()

    # If 'all', no filtering needed
    if min_severity == 'all':
        return findings

    # Severity ranking (lower number = higher severity)
    severity_rank = {
        'critical': 1,
        'high': 2,
        'medium': 3,
        'low': 4
    }

    min_rank = severity_rank.get(min_severity, 4)  # Default to 'low' if invalid

    filtered_findings = []
    code_quality_filtered_count = 0

    for finding in findings:
        category = finding.get('category', 'security')
        severity = finding.get('severity', 'low').lower()

        # Security findings are ALWAYS included (not affected by code quality filter)
        if category != 'code_quality':
            filtered_findings.append(finding)
            continue

        # Code quality findings: filter by severity
        finding_rank = severity_rank.get(severity, 4)

        if finding_rank <= min_rank:
            # Include findings with severity >= min_severity
            filtered_findings.append(finding)
        else:
            code_quality_filtered_count += 1
            logger.debug(f"❌ Filtered out code_quality finding: {finding.get('check_id', 'unknown')} [{severity}] (min_severity={min_severity})")

    if code_quality_filtered_count > 0:
        logger.info(f"🔽 Code quality filtering: Removed {code_quality_filtered_count} findings below '{min_severity}' severity")

    return filtered_findings
