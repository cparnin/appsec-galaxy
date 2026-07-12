import subprocess
import json
from pathlib import Path
import logging

# Import configuration constants
from appsec_galaxy.config import format_subprocess_error
from appsec_galaxy.finding import Finding
from appsec_galaxy.project_paths import CONFIGS_DIR
from .validation import validate_binary_path, validate_repo_path

logger = logging.getLogger(__name__)

def run_gitleaks(repo_path: str, output_dir: Path | None = None) -> list:
    """
    Run Gitleaks scanner on the given repository path.
    Returns a list of findings in standardized format.

    Args:
        repo_path: Path to repository to scan
        output_dir: Directory for output files (defaults to ../outputs/raw)
    """
    try:
        # Use provided output_dir or default
        if output_dir is None:
            from appsec_galaxy.config import BASE_OUTPUT_DIR
            output_dir = Path(BASE_OUTPUT_DIR) / "raw"
        else:
            output_dir = Path(output_dir)

        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / "gitleaks.json"

        # Get and validate Gitleaks binary path
        gitleaks_bin = validate_binary_path('GITLEAKS_BIN', 'gitleaks')
        if not gitleaks_bin:
            logger.error("Could not validate gitleaks binary")
            return []

        # Validate and sanitize repo path
        repo_path_obj = validate_repo_path(repo_path)
        if not repo_path_obj:
            return []

        git_dir = repo_path_obj / ".git"
        logger.debug(f"Scanning repository at: {repo_path_obj}")
        logger.debug(f"Git directory exists: {git_dir.exists()}")
        logger.debug(f"Output file will be: {output_file}")

        # Delete old output file BEFORE running to prevent loading stale results
        if output_file.exists():
            output_file.unlink()
            logger.debug(f"Deleted old gitleaks output file: {output_file}")

        # Run Gitleaks with custom config and output JSON results
        config_path = CONFIGS_DIR / ".gitleaks.toml"
        cmd = [
            gitleaks_bin, "detect",
            "--source", str(repo_path_obj),
            "--config", str(config_path),
            "--report-format", "json",
            "--report-path", str(output_file),
            "--no-banner",
            "--exit-code", "0"  # Don't fail CI on findings
        ]

        logger.debug(f"Gitleaks command: {' '.join(cmd)}")

        # Use subprocess.run with shell=False for security
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, shell=False)

        # Log output for debugging
        if result.stdout:
            logger.debug(f"Gitleaks stdout: {result.stdout}")
        if result.stderr:
            logger.debug(f"Gitleaks stderr: {result.stderr}")

        # Gitleaks exits with code 1 when it finds secrets, which is normal
        if result.returncode not in (0, 1):
            error_details = format_subprocess_error('gitleaks', result.returncode, result.stderr, result.stdout)
            logger.error(error_details)
            return []

        # Check if output file exists and parse results
        logger.debug(f"Checking for output file: {output_file}")
        if output_file.exists():
            logger.debug(f"Output file size: {output_file.stat().st_size} bytes")

            # Handle potential UTF-8 decode errors gracefully
            with open(output_file, encoding="utf-8", errors="replace") as f:
                content = f.read().strip()

            logger.debug(f"Output file content length: {len(content)} characters")

            if not content:
                logger.debug("Gitleaks found no secrets (empty output)")
                return []

            try:
                results = json.loads(content)
                if isinstance(results, list):
                    # Normalize through the canonical Finding boundary
                    # (adds category + tool; raw gitleaks keys preserved)
                    normalized = [Finding.from_gitleaks(f).to_dict() for f in results]
                    logger.debug(f"Gitleaks found {len(normalized)} potential secrets")
                    return normalized
                else:
                    logger.warning(f"Unexpected Gitleaks output format: {type(results)}")
                    return []
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Gitleaks JSON output: {e}")
                logger.debug(f"Raw content: {content[:500]}...")  # First 500 chars
                return []
        else:
            logger.debug("Gitleaks found no secrets (no output file)")
            return []

    except subprocess.TimeoutExpired:
        timeout_msg = format_subprocess_error('gitleaks', 124, "Process timed out after 2 minutes")
        logger.error(timeout_msg)
        return []
    except FileNotFoundError:
        not_found_msg = format_subprocess_error('gitleaks', 127, "Gitleaks command not found in PATH")
        logger.error(not_found_msg)
        return []
    except Exception as e:
        generic_msg = format_subprocess_error('gitleaks', 1, str(e))
        logger.error(generic_msg)
        return []
