"""
Path utilities for managing multi-repository output structure.

Provides automatic detection of git context and intelligent output path generation
while maintaining backward compatibility with non-git repositories.

Each repository has one canonical output directory containing the most recent scan.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path
from appsec_galaxy.logging_config import get_logger

logger = get_logger(__name__)


def sanitize_path_component(name: str) -> str:
    """
    Convert repo/branch names to safe filesystem paths.

    Handles:
    - Slashes in branch names (feature/auth-fix → feature_auth-fix)
    - Organization/repo format (my-org/my-repo → my-org_my-repo)
    - Special filesystem characters

    Args:
        name: Repository or branch name

    Returns:
        Safe filesystem path component
    """
    if not name:
        return "unknown"

    # Replace path separators with underscores
    safe_name = name.replace('/', '_').replace('\\', '_')

    # Remove filesystem-problematic characters
    safe_name = re.sub(r'[<>:"|?*]', '', safe_name)

    # Remove leading/trailing dots and spaces
    safe_name = safe_name.strip('. ')

    # Ensure not empty after sanitization
    if not safe_name:
        return "unknown"

    return safe_name


def get_git_context(repo_path: str) -> dict[str, str] | None:
    """
    Extract repository name and branch from git repository.

    Args:
        repo_path: Path to repository

    Returns:
        Dict with 'repo' and 'branch' keys, or None if not a git repo
    """
    try:
        repo_path = Path(repo_path).resolve()

        # Check if it's a git repository
        result = subprocess.run(
            ['git', 'rev-parse', '--git-dir'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode != 0:
            logger.debug(f"Not a git repository: {repo_path}")
            return None

        # Get current branch
        branch_result = subprocess.run(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5
        )

        if branch_result.returncode != 0:
            logger.warning("Could not determine git branch")
            branch = "main"
        else:
            branch = branch_result.stdout.strip()
            if not branch:
                branch = "main"

        # Get repository name from remote URL
        remote_result = subprocess.run(
            ['git', 'config', '--get', 'remote.origin.url'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=5
        )

        if remote_result.returncode != 0 or not remote_result.stdout.strip():
            # No remote configured, use directory name
            repo_name = repo_path.name
            logger.debug(f"No git remote found, using directory name: {repo_name}")
        else:
            remote_url = remote_result.stdout.strip()
            # Parse various URL formats:
            # git@github.com:user/repo.git
            # https://github.com/user/repo.git
            # https://github.com/user/repo

            # Remove .git suffix
            remote_url = remote_url.rstrip('.git')

            # Extract repo name from URL
            if 'github.com' in remote_url or 'gitlab.com' in remote_url:
                # Format: user/repo or org/repo
                parts = remote_url.split('/')[-2:]
                if len(parts) == 2:
                    # Keep the org/user and repo together
                    repo_name = f"{parts[0]}_{parts[1]}"
                else:
                    repo_name = remote_url.split('/')[-1]
            else:
                # Generic git URL, use last component
                repo_name = remote_url.split('/')[-1]

            # Handle git@ format
            if ':' in repo_name and '@' in repo_name:
                repo_name = repo_name.split(':')[-1]

        logger.debug(f"Git context detected - repo: {repo_name}, branch: {branch}")

        return {
            'repo': repo_name,
            'branch': branch
        }

    except subprocess.TimeoutExpired:
        logger.warning("Git command timed out while detecting context")
        return None
    except Exception as e:
        logger.debug(f"Could not extract git context: {e}")
        return None


def get_output_path(repo_path: str, base_output_dir: str = "outputs") -> Path:
    """
    Get output path for scan results with per-repository structure.

    Strategy:
    - If git repo with remote: outputs/repo_name/
    - If git repo without remote: outputs/dir_name/
    - If not git repo: outputs/dir_name/

    This ensures:
    - Multi-repository support without conflicts
    - Simple, predictable output structure
    - Natural namespace isolation
    - No branch-level complexity

    Each repository has one canonical output location containing the most recent scan.

    Args:
        repo_path: Path to repository being scanned
        base_output_dir: Base output directory (default: "outputs")

    Returns:
        Path object for output directory
    """
    repo_path = Path(repo_path).resolve()
    base_path = Path(base_output_dir)

    # Use directory name directly (simpler and more predictable)
    # Git detection can be confused by parent directories
    safe_repo = sanitize_path_component(repo_path.name)
    logger.debug(f"Using directory name for output: {safe_repo}")

    output_path = base_path / safe_repo

    logger.debug(f"Output path: {output_path}")

    return output_path


def purge_stale_outputs(base_output_dir: Path) -> int:
    """Delete per-repo output dirs with no scan activity within the
    retention window (APPSEC_OUTPUT_RETENTION_DAYS, default 30; 0 disables).

    Returns the number of directories purged. Fails open: any error means
    nothing is deleted.
    """
    import time

    raw_days = os.getenv('APPSEC_OUTPUT_RETENTION_DAYS', '30').strip()
    try:
        days = int(raw_days)
    except ValueError:
        logger.warning(f"Invalid APPSEC_OUTPUT_RETENTION_DAYS={raw_days!r}; using 30")
        days = 30
    if days <= 0:
        return 0

    base = Path(base_output_dir)
    if not base.is_dir():
        return 0

    cutoff = time.time() - days * 86400
    purged = 0
    for entry in base.iterdir():
        if not entry.is_dir():
            continue
        try:
            # Last scan activity: history.json is touched on every scan;
            # fall back to the directory's own mtime.
            history = entry / 'history.json'
            last_activity = history.stat().st_mtime if history.exists() else entry.stat().st_mtime
            if last_activity < cutoff:
                shutil.rmtree(entry)
                purged += 1
                logger.info(f"Retention: purged stale scan outputs {entry} (>{days}d old)")
        except OSError as e:
            logger.warning(f"Retention: could not evaluate/purge {entry}: {e}")
    return purged


def cleanup_old_scans(output_path: Path) -> None:
    """
    Remove old scan results, keeping only the most recent scan for the repository.

    Strategy:
    - Delete all existing contents in the output path
    - This ensures only the current scan exists
    - Prevents disk space accumulation
    - history.json survives: it holds cross-scan trend data (new vs fixed
      deltas) and deleting it would reset the trend on every scan

    Args:
        output_path: Path to the repository output directory
    """
    # Retention sweep across sibling repos first: outputs/<repo>/ dirs from
    # old engagements accumulate forever otherwise (raw scanner output can
    # contain detected client secrets, so aging it out matters).
    purge_stale_outputs(output_path.parent)

    preserve = {'history.json'}
    try:
        if output_path.exists():
            logger.debug(f"Cleaning up old scan results in {output_path}")

            # Remove all subdirectories and files (except cross-scan state)
            for item in output_path.iterdir():
                if item.name in preserve:
                    continue
                if item.is_dir():
                    shutil.rmtree(item)
                else:
                    item.unlink()

            logger.debug("Cleaned up old scan results")
        else:
            # Create the directory structure
            output_path.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Created output directory: {output_path}")

    except Exception as e:
        logger.warning(f"Could not cleanup old scans: {e}")
        # Not critical - continue with scan


def setup_output_directories(output_path: Path) -> dict[str, Path]:
    """
    Create output directory structure for scan results.

    Structure:
    outputs/repo_name/branch/
        ├── raw/           # Raw scanner JSON outputs
        ├── sbom/          # SBOM compliance files
        └── report.html    # HTML report (root level)

    Args:
        output_path: Base output path for the repository/branch

    Returns:
        Dict with paths for 'base', 'raw', 'sbom'
    """
    try:
        # Create main directories
        output_path.mkdir(parents=True, exist_ok=True)

        raw_dir = output_path / "raw"
        sbom_dir = output_path / "sbom"

        raw_dir.mkdir(exist_ok=True)
        sbom_dir.mkdir(exist_ok=True)

        logger.debug(f"Output directories ready: {output_path}")

        return {
            'base': output_path,
            'raw': raw_dir,
            'sbom': sbom_dir
        }

    except Exception as e:
        logger.error(f"Failed to create output directories: {e}")
        raise


def get_report_path(output_path: Path) -> Path:
    """Get path for HTML report."""
    return output_path / "report.html"


def get_pr_findings_path(output_path: Path) -> Path:
    """Get path for PR findings text file."""
    return output_path / "pr-findings.txt"


def list_available_scans(base_output_dir: str = "outputs") -> dict[str, Path]:
    """
    List all available scan results organized by repository.

    Args:
        base_output_dir: Base output directory

    Returns:
        Dict structure: {repo_name: path, ...}
    """
    base_path = Path(base_output_dir)

    if not base_path.exists():
        return {}

    scans = {}

    try:
        for repo_dir in base_path.iterdir():
            if not repo_dir.is_dir():
                continue

            repo_name = repo_dir.name

            # Check if scan results exist
            if (repo_dir / "report.html").exists():
                scans[repo_name] = repo_dir

        return scans

    except Exception as e:
        logger.warning(f"Could not list available scans: {e}")
        return {}
