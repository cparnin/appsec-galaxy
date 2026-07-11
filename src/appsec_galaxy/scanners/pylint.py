"""
Pylint code quality scanner integration for Python projects.

This module runs Pylint to detect code quality issues, best practices violations,
code smells, and potential bugs in Python codebases.
"""

import subprocess
import json
from pathlib import Path

from appsec_galaxy.config import format_subprocess_error
from .validation import validate_repo_path
from appsec_galaxy.logging_config import get_logger

logger = get_logger(__name__)


def check_pylint_installed() -> bool:
    """
    Check if Pylint is available in the system.

    Returns:
        bool: True if Pylint is installed and accessible
    """
    try:
        result = subprocess.run(
            ['pylint', '--version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            version = result.stdout.strip().split('\n')[0]
            logger.debug(f"Pylint found: {version}")
            return True
        return False
    except FileNotFoundError:
        logger.debug("Pylint not found in PATH")
        return False
    except Exception as e:
        logger.debug(f"Error checking Pylint installation: {e}")
        return False


def _map_pylint_severity(pylint_type: str) -> str:
    """
    Map Pylint message types to AppSec Galaxy standard severity.

    Pylint uses:
    - convention (C): coding standard violation
    - refactor (R): code smell
    - warning (W): minor issues
    - error (E): probable bugs
    - fatal (F): prevents further processing

    Args:
        pylint_type: Pylint message type (C, R, W, E, F)

    Returns:
        str: Normalized severity ('low', 'medium', 'high')
    """
    severity_map = {
        'convention': 'low',     # C: coding standards
        'refactor': 'medium',    # R: code smells, refactoring suggestions
        'warning': 'medium',     # W: potential issues
        'error': 'high',         # E: likely bugs
        'fatal': 'critical'      # F: critical errors
    }
    return severity_map.get(pylint_type.lower(), 'medium')


def _get_subcategory(message_id: str, symbol: str) -> str:
    """
    Determine subcategory based on Pylint message ID or symbol.

    Args:
        message_id: Pylint message ID (e.g., 'C0103')
        symbol: Pylint message symbol (e.g., 'invalid-name')

    Returns:
        str: Subcategory for the finding
    """
    # Categorize based on message prefix or symbol
    if symbol:
        if any(keyword in symbol for keyword in ['unused', 'redundant', 'duplicate']):
            return 'dead-code'
        elif any(keyword in symbol for keyword in ['name', 'naming', 'convention']):
            return 'naming-convention'
        elif any(keyword in symbol for keyword in ['import', 'module']):
            return 'import-issues'
        elif any(keyword in symbol for keyword in ['complexity', 'too-many', 'too-few']):
            return 'complexity'
        elif any(keyword in symbol for keyword in ['format', 'whitespace', 'line']):
            return 'code-style'

    return 'best-practice'


def _normalize_pylint_finding(message: dict, repo_path: Path) -> dict:
    """
    Convert Pylint finding to AppSec Galaxy standard format.

    Args:
        message: Pylint message object
        repo_path: Root path of the repository

    Returns:
        dict: Normalized finding in AppSec Galaxy format
    """
    # Make path relative to repo root
    try:
        file_path = Path(message.get('path', message.get('file', '')))
        relative_path = file_path.relative_to(repo_path)
    except (ValueError, TypeError):
        relative_path = Path(message.get('path', message.get('file', 'unknown')))

    pylint_type = message.get('type', 'warning')
    normalized_severity = _map_pylint_severity(pylint_type)

    symbol = message.get('symbol', '')
    message_id = message.get('message-id', '')
    subcategory = _get_subcategory(message_id, symbol)

    return {
        'tool': 'pylint',
        'category': 'code_quality',
        'severity': normalized_severity,
        'check_id': f"pylint.{symbol}" if symbol else f"pylint.{message_id}",
        'path': str(relative_path),
        'start': {
            'line': message.get('line', 0),
            'col': message.get('column', 0)
        },
        'end': {
            'line': message.get('endLine', message.get('line', 0)),
            'col': message.get('endColumn', message.get('column', 0))
        },
        'extra': {
            'message': message.get('message', ''),
            'metadata': {
                'category': 'code_quality',
                'subcategory': subcategory,
                'technology': ['python'],
                'confidence': 'HIGH',
                'pylint_type': pylint_type,
                'pylint_id': message_id
            }
        }
    }


def run_pylint(repo_path: str, output_dir: str = None) -> list:
    """
    Run Pylint code quality scanner on Python files.

    Args:
        repo_path: Path to repository to scan
        output_dir: Directory for output files (defaults to ../outputs/raw)

    Returns:
        list: List of findings in standardized AppSec Galaxy format
    """
    try:
        # Check if Pylint is installed
        if not check_pylint_installed():
            logger.warning("⚠️ Pylint not installed - skipping code quality scan for Python")
            logger.info("💡 Install Pylint: pip install pylint")
            return []

        # Set up output directory
        if output_dir is None:
            from appsec_galaxy.config import BASE_OUTPUT_DIR
            output_path = Path(BASE_OUTPUT_DIR) / "raw"
        else:
            output_path = Path(output_dir)

        output_path.mkdir(parents=True, exist_ok=True)
        output_file = output_path / "pylint.json"

        # Validate repo path
        repo_path_obj = validate_repo_path(repo_path)
        if not repo_path_obj:
            logger.error(f"Repository path validation failed: {repo_path}")
            return []

        logger.debug(f"Starting Pylint scan of {repo_path_obj}")

        # Find Python files in repository
        python_files = []
        for ext in ['.py']:
            python_files.extend(repo_path_obj.rglob(f'*{ext}'))

        # Filter out excluded directories
        filtered_files = []
        for py_file in python_files:
            # Check if file is in an excluded directory
            path_parts = py_file.parts
            if any(excluded in path_parts for excluded in ['node_modules', '.git', '__pycache__',
                                                            '.venv', 'venv', 'dist', 'build',
                                                            '.cache', 'outputs', '.pytest_cache']):
                continue
            filtered_files.append(py_file)

        if not filtered_files:
            logger.info("No Python files found to scan")
            return []

        logger.debug(f"Found {len(filtered_files)} Python files to scan")

        # Build Pylint command
        cmd = [
            'pylint',
            '--output-format=json',
            '--reports=no',  # Disable report generation
            '--score=no',    # Disable score
        ]

        # Disable some overly noisy checks for code quality scanning
        cmd.extend([
            '--disable=C0114',  # missing-module-docstring
            '--disable=C0115',  # missing-class-docstring
            '--disable=C0116',  # missing-function-docstring
            '--disable=R0903',  # too-few-public-methods
            '--disable=E0401',  # import-error (false positives when scanning external repos)
            '--max-line-length=120'  # More reasonable than default 100
        ])

        # Add Python files (convert to strings relative to repo root)
        for py_file in filtered_files[:500]:  # Limit to 500 files to prevent timeout
            try:
                relative_file = py_file.relative_to(repo_path_obj)
                cmd.append(str(relative_file))
            except ValueError:
                cmd.append(str(py_file))

        if len(filtered_files) > 500:
            logger.warning(f"Scanning only first 500 of {len(filtered_files)} Python files (performance limit)")

        logger.debug(f"Pylint scanning {len(cmd) - 6} Python files")

        # Delete old output file
        if output_file.exists():
            output_file.unlink()
            logger.debug(f"Deleted old Pylint output file: {output_file}")

        # Run Pylint
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            shell=False,
            cwd=str(repo_path_obj)
        )

        logger.debug(f"Pylint completed with return code: {result.returncode}")

        # Pylint returns non-zero if issues found, which is expected
        # Only treat return codes >= 32 as errors
        if result.returncode >= 32:
            error_details = format_subprocess_error('pylint', result.returncode, result.stderr, result.stdout)
            logger.error(error_details)
            return []

        # Parse Pylint JSON output from stdout
        try:
            if result.stdout:
                pylint_results = json.loads(result.stdout)
            else:
                logger.warning("Pylint produced no output")
                return []
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Pylint JSON output: {e}")
            logger.debug(f"Pylint stdout: {result.stdout[:500]}")
            return []

        logger.debug(f"Pylint found {len(pylint_results)} issues")

        # Normalize findings
        findings = []
        for message in pylint_results:
            normalized = _normalize_pylint_finding(message, repo_path_obj)
            findings.append(normalized)

        # Write results to file for debugging
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=2)

        logger.info(f"✅ Pylint: {len(findings)} code quality issues found")

        return findings

    except subprocess.TimeoutExpired:
        timeout_msg = format_subprocess_error('pylint', 124, "Process timed out after 5 minutes")
        logger.error(timeout_msg)
        return []
    except FileNotFoundError:
        logger.warning("Pylint command not found - skipping Python code quality scan")
        logger.info("💡 Install Pylint: pip install pylint")
        return []
    except Exception as e:
        error_msg = format_subprocess_error('pylint', 1, str(e))
        logger.error(error_msg)
        return []
