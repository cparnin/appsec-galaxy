"""
Configuration constants for AppSec Galaxy.

Truly hardcoded values live here. User-configurable knobs stay in `.env`
(see env.example). The history of which knobs got promoted to constants vs.
kept as env vars is in CHANGELOG.md; the rule of thumb: anything nobody
tunes in practice should be hardcoded.
"""

# Tool installation URLs (used in error messages)
TOOL_INSTALL_URLS = {
    'semgrep': "pip install semgrep",
    'gitleaks': "https://github.com/gitleaks/gitleaks#installing",
    'trivy': "https://trivy.dev/getting-started/installation/"
}

# Repository discovery settings
MAX_REPO_SEARCH_DEPTH = 2

# Pipeline safety - files that should never be modified
PROTECTED_FILE_PATTERNS = [
    # CI/CD Pipeline files
    '.github/workflows/',
    '.github/actions/',
    'action.yml',
    'action.yaml',
    '.gitlab-ci.yml',     # GitLab CI
    'azure-pipelines.yml', # Azure DevOps
    'jenkinsfile',        # Jenkins (case insensitive match)
    'Jenkinsfile',        # Jenkins
    '.circleci/',         # CircleCI
    '.buildkite/',        # Buildkite
    'appveyor.yml',       # AppVeyor
    '.travis.yml',        # Travis CI

    # Docker ignore and build context files (not security-related)
    '.dockerignore',      # Docker ignore patterns (build context)

    # Kubernetes and orchestration
    'k8s/',              # Kubernetes manifests
    'kubernetes/',       # Kubernetes manifests
    'helm/',             # Helm charts
    '.helm/',            # Helm configuration

    # Infrastructure as Code
    'terraform/',        # Terraform configurations
    'infrastructure/',   # Common IaC directory
    'cloudformation/',   # AWS CloudFormation
    'pulumi/',          # Pulumi IaC

    # Scanner output directories
    'outputs/',           # Don't modify scanner output files
    'outputs/sbom/',      # Don't modify SBOM files
    'outputs/raw/',       # Don't modify raw scan results
    'outputs/reports/'    # Don't modify generated reports
]

# Files/directories to exclude from security scanning
SCAN_EXCLUDE_PATTERNS = [
    'outputs/',           # Scanner output directory
    '.git/',              # Git metadata
    'node_modules/',      # Node.js dependencies
    '__pycache__/',       # Python cache
    '.venv/',             # Python virtual environment
    'venv/',              # Python virtual environment
    'dist/',              # Build outputs
    'build/',             # Build outputs
    '.cache/',            # Various cache directories
]

# Dependency file patterns for scanning
DEPENDENCY_FILE_PATTERNS = [
    "package.json", "package-lock.json", "yarn.lock",        # Node.js
    "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",  # Python
    "go.mod", "go.sum",                                      # Go
    "Cargo.toml", "Cargo.lock",                             # Rust
    "composer.json", "composer.lock",                       # PHP
    "pom.xml", "build.gradle"                               # Java
]

# Default values (fallbacks when env vars not set)
DEFAULT_MANUAL_REVIEW_TIME = 0.5  # hours per finding
DEFAULT_TOOL_CHECK_TIMEOUT = 10   # seconds

# Git-aware scanning settings
ENABLE_GIT_AWARE_SCANNING = True  # Can be disabled via env var
MAX_CHANGED_FILES_FOR_FULL_SCAN = 100  # If more files changed, do full scan
GIT_DIFF_CONTEXT_LINES = 3  # Lines of context around changes

# Typed, validated env config (pydantic-settings).
# Invalid values (e.g. APPSEC_AI_SCAN_MAX_FILES=abc, APPSEC_AI_SCAN_DEPTH=fast)
# fail loudly at startup with a clear message instead of being silently
# coerced or defaulted. Module-level constant names below are unchanged, so
# all existing `from config import X` imports keep working.
import os

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSecGalaxySettings(BaseSettings):
    """All APPSEC_* env vars consumed by config.py, validated at startup."""

    model_config = SettingsConfigDict(extra="ignore", populate_by_name=True)

    # Code quality scanning (ON by default). Linter findings filtered by
    # min severity: critical, high, medium, low, all.
    code_quality: bool = Field(default=True, alias="APPSEC_CODE_QUALITY")
    code_quality_min_severity: str = Field(default="high", alias="APPSEC_CODE_QUALITY_MIN_SEVERITY")

    # AI-native scanner (opt-in). Depth selects quick, standard, or deep.
    # Tier is client privacy:
    # 1 = no AI calls at all
    # 2 = metadata only (AI exec summary runs on finding paths/lines/rules/
    #     messages; no source files, no AI scanner, no AI cross-file)
    # 3 = full source files sent to the AI scanner (default)
    # Gates are split across scanners/ai_scanner.py and ai_cross_file.py
    # (`tier < 3`) and reporting/ai_summary.py (`tier < 2`).
    ai_scan: bool = Field(default=False, alias="APPSEC_AI_SCAN")
    ai_scan_depth: str = Field(default="standard", alias="APPSEC_AI_SCAN_DEPTH")
    ai_scan_max_files: int = Field(default=50, ge=1, alias="APPSEC_AI_SCAN_MAX_FILES")
    ai_scan_tier: int = Field(default=3, ge=1, le=3, alias="APPSEC_AI_SCAN_TIER")

    # Dependency code-path analysis and registry health checks.
    dependency_analysis: bool = Field(default=True, alias="APPSEC_DEPENDENCY_ANALYSIS")
    dep_health_check: bool = Field(default=True, alias="APPSEC_DEP_HEALTH_CHECK")

    # Trivy scanner selection: comma-separated subset of {vuln, misconfig}.
    # misconfig covers IaC and config files (Terraform, CloudFormation, K8s
    # manifests, Dockerfile). Set to "vuln" for the old deps-only behavior.
    trivy_scanners: str = Field(default="vuln,misconfig", alias="APPSEC_TRIVY_SCANNERS")

    @field_validator("code_quality_min_severity", mode="before")
    @classmethod
    def _check_severity(cls, v: str) -> str:
        v = str(v).lower().strip()
        valid = {"critical", "high", "medium", "low", "all"}
        if v not in valid:
            raise ValueError(f"APPSEC_CODE_QUALITY_MIN_SEVERITY must be one of {sorted(valid)}, got '{v}'")
        return v

    @field_validator("ai_scan_depth", mode="before")
    @classmethod
    def _check_depth(cls, v: str) -> str:
        v = str(v).lower().strip()
        valid = {"quick", "standard", "deep"}
        if v not in valid:
            raise ValueError(f"APPSEC_AI_SCAN_DEPTH must be one of {sorted(valid)}, got '{v}'")
        return v

    @field_validator("trivy_scanners", mode="before")
    @classmethod
    def _check_trivy_scanners(cls, v: str) -> str:
        parts = [p.strip().lower() for p in str(v).split(",") if p.strip()]
        valid = {"vuln", "misconfig"}
        if not parts or any(p not in valid for p in parts):
            raise ValueError(
                f"APPSEC_TRIVY_SCANNERS must be a comma-separated subset of {sorted(valid)}, got '{v}'"
            )
        return ",".join(dict.fromkeys(parts))


settings = AppSecGalaxySettings()

# Backwards-compatible module-level constants (canonical import surface)
ENABLE_CODE_QUALITY = settings.code_quality
CODE_QUALITY_MIN_SEVERITY = settings.code_quality_min_severity
ENABLE_AI_SCAN = settings.ai_scan
AI_SCAN_DEPTH = settings.ai_scan_depth
AI_SCAN_MAX_FILES = settings.ai_scan_max_files
AI_SCAN_TIER = settings.ai_scan_tier
TRIVY_SCANNERS = settings.trivy_scanners

# Minimum confidence threshold for AI findings (0.0-1.0).
# Hardcoded: nobody tunes this in production, and exposing it as an env var
# invited inconsistency (the value was previously read in two places with
# the same default).
AI_SCAN_MIN_CONFIDENCE = 0.7

# Tool Selection (CLI/Web only - MCP and CI/CD always run all)
# Parse APPSEC_TOOLS environment variable
# Format: comma-separated list (e.g., "semgrep,gitleaks,trivy")
# Valid options: semgrep, trivy, gitleaks, code_quality, sbom, ai_scan, all
def parse_tool_selection(tools_string: str | None = None) -> set:
    """
    Parse and validate tool selection from environment or parameter.

    Args:
        tools_string: Comma-separated tool names, defaults to APPSEC_TOOLS env var

    Returns:
        set: Set of validated tool names
    """
    if tools_string is None:
        tools_string = os.getenv('APPSEC_TOOLS', 'all')

    # Normalize and split
    tools_string = tools_string.lower().strip()

    # If 'all', return all tools
    if tools_string == 'all':
        all_tools = {'semgrep', 'trivy', 'gitleaks', 'code_quality', 'sbom'}
        if ENABLE_AI_SCAN:
            all_tools.add('ai_scan')
        return all_tools

    # Parse individual tools
    tools = set()
    valid_tools = {'semgrep', 'trivy', 'gitleaks', 'code_quality', 'sbom', 'ai_scan'}

    for tool in tools_string.split(','):
        tool = tool.strip()
        if tool in valid_tools:
            tools.add(tool)
        elif tool:  # Only warn if non-empty
            import logging
            logging.warning(f"Invalid tool '{tool}' ignored. Valid options: {', '.join(sorted(valid_tools))}")

    # Ensure at least one tool is selected
    if not tools:
        import logging
        logging.warning("No valid tools selected, defaulting to 'all'")
        return {'semgrep', 'trivy', 'gitleaks', 'code_quality', 'sbom'}

    return tools

# Default tool selection for current session
SELECTED_TOOLS = parse_tool_selection()

# AI temperature for fix generation. Hardcoded at 0.0: any other value
# breaks deterministic fixes, which is the whole point of auto-remediation.
# Used to be an env var that only had one valid setting.
AI_TEMPERATURE = 0.0

# Dependency Code Path Analysis (validated via AppSecGalaxySettings above)
ENABLE_DEPENDENCY_ANALYSIS = settings.dependency_analysis

# Health check against package registries (npm, PyPI, etc.)
DEPENDENCY_HEALTH_CHECK = settings.dep_health_check

# Depth score threshold below which a dependency is trivially inlineable.
# Internal heuristic, not customer-facing.
DEPENDENCY_INLINE_THRESHOLD = 0.3

# Package staleness thresholds (months since last publish). Aligned with the
# values previously documented in env.example.
PACKAGE_STALE_MONTHS = 18
PACKAGE_ABANDONED_MONTHS = 36

# Cache TTL for registry lookups (seconds). Internal detail; 1 hour is plenty
# for a single scan session.
REGISTRY_CACHE_TTL = 3600

# Output path management
from appsec_galaxy.project_paths import OUTPUTS_DIR

BASE_OUTPUT_DIR = str(OUTPUTS_DIR)  # Base directory for all scan results

def format_subprocess_error(tool_name: str, returncode: int, stderr: str, stdout: str = "") -> str:
    """
    Format subprocess errors with helpful context and troubleshooting tips.

    Args:
        tool_name: Name of the tool that failed
        returncode: Process return code
        stderr: Standard error output
        stdout: Standard output (optional)

    Returns:
        str: Formatted error message with troubleshooting guidance
    """
    error_msg = f"\n❌ {tool_name.capitalize()} failed (exit code {returncode})"

    # Add tool-specific troubleshooting
    troubleshooting = {
        'semgrep': {
            'common_issues': [
                "Large repository (try excluding node_modules, .git, etc.)",
                "Network issues downloading rules",
                "Insufficient memory for large files"
            ],
            'solutions': [
                "Add --exclude=node_modules --exclude=.git to semgrep config",
                "Check internet connection for rule downloads",
                "Increase available memory or scan smaller directories"
            ]
        },
        'gitleaks': {
            'common_issues': [
                "Git repository not initialized",
                "Corrupted git history",
                "Large binary files in git history"
            ],
            'solutions': [
                "Ensure directory is a valid git repository",
                "Try: git fsck --full",
                "Use .gitleaksignore to exclude problematic files"
            ]
        },
        'trivy': {
            'common_issues': [
                "Network issues downloading vulnerability database",
                "No supported dependency files found",
                "Insufficient disk space for cache"
            ],
            'solutions': [
                "Check internet connection and firewall settings",
                "Ensure package files exist (package.json, requirements.txt, etc.)",
                "Clear trivy cache: trivy clean --all"
            ]
        }
    }

    # Add stderr/stdout if helpful
    if stderr and len(stderr.strip()) > 0:
        # Clean up common noise in stderr
        clean_stderr = stderr.strip()
        if len(clean_stderr) > 200:
            clean_stderr = clean_stderr[:200] + "..."
        error_msg += f"\n   Error output: {clean_stderr}"

    # Add tool-specific troubleshooting
    tool_lower = tool_name.lower()
    if tool_lower in troubleshooting:
        error_msg += f"\n\n🔧 Common causes for {tool_name}:"
        for issue in troubleshooting[tool_lower]['common_issues']:
            error_msg += f"\n   • {issue}"

        error_msg += "\n\n💡 Try these solutions:"
        for solution in troubleshooting[tool_lower]['solutions']:
            error_msg += f"\n   • {solution}"

    # Add general troubleshooting
    error_msg += "\n\n📋 General troubleshooting:"
    error_msg += f"\n   • Check tool installation: {tool_name} --version"
    error_msg += "\n   • Verify file permissions in scan directory"
    error_msg += f"\n   • Try running {tool_name} manually on a small test directory"

    return error_msg
