"""
Shared pytest fixtures and configuration for the AppSec Galaxy test suite.

This module provides reusable fixtures for testing security scanners,
validation functions, and other AppSec Galaxy components.
"""

import json
import os
import shutil
import tempfile
from pathlib import Path

import pytest

# Never load a developer's real .env mid-session: several tests reimport
# appsec_galaxy.main, which calls load_dotenv() at import time, and that
# would put live provider keys into the environment after the AI test
# fixtures have already cleaned it.
os.environ.setdefault("PYTHON_DOTENV_DISABLED", "1")


@pytest.fixture
def temp_dir():
    """Create a temporary directory that is cleaned up after the test."""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def mock_repo(temp_dir):
    """Create a mock repository structure for testing."""
    repo_path = temp_dir / "test_repo"
    repo_path.mkdir()

    # Create a .git directory to simulate a git repo
    git_dir = repo_path / ".git"
    git_dir.mkdir()

    # Create some sample files
    (repo_path / "app.py").write_text("""
import os
password = "hardcoded_secret"

def vulnerable_function(user_input):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query
""")

    (repo_path / "config.js").write_text("""
const API_KEY = "sk-1234567890abcdef";
module.exports = { API_KEY };
""")

    (repo_path / "package.json").write_text(json.dumps({
        "name": "test-app",
        "version": "1.0.0",
        "dependencies": {
            "express": "4.17.1",
            "lodash": "4.17.19"
        }
    }))

    (repo_path / "requirements.txt").write_text("""
flask==1.1.2
requests==2.25.1
""")

    return repo_path



@pytest.fixture
def sample_semgrep_output():
    """Sample Semgrep JSON output for testing."""
    return {
        "results": [
            {
                "check_id": "python.lang.security.audit.dangerous-system-call.dangerous-system-call",
                "path": "app.py",
                "line": 10,
                "column": 5,
                "end_line": 10,
                "end_column": 25,
                "message": "Detected dangerous use of os.system(). Use subprocess instead.",
                "severity": "ERROR",
                "metadata": {
                    "category": "security",
                    "technology": ["python"],
                    "cwe": ["CWE-78: OS Command Injection"]
                }
            },
            {
                "check_id": "python.lang.security.audit.hardcoded-password.hardcoded-password",
                "path": "app.py",
                "line": 5,
                "column": 1,
                "end_line": 5,
                "end_column": 30,
                "message": "Hardcoded password detected",
                "severity": "WARNING",
                "metadata": {
                    "category": "security",
                    "technology": ["python"]
                }
            }
        ],
        "errors": []
    }


@pytest.fixture
def sample_gitleaks_output():
    """Sample Gitleaks JSON output for testing."""
    return [
        {
            "Description": "Generic API Key",
            "StartLine": 1,
            "EndLine": 1,
            "StartColumn": 13,
            "EndColumn": 33,
            "Match": "sk-1234567890abcdef",
            "Secret": "sk-1234567890abcdef",
            "File": "config.js",
            "Commit": "abc123def456",
            "Entropy": 3.5,
            "Author": "test@example.com",
            "Date": "2023-01-01T00:00:00Z",
            "Message": "Add API key",
            "RuleID": "generic-api-key"
        }
    ]


@pytest.fixture
def sample_trivy_output():
    """Sample Trivy JSON output for testing."""
    return {
        "SchemaVersion": 2,
        "ArtifactName": "package-lock.json",
        "ArtifactType": "npm",
        "Results": [
            {
                "Target": "package-lock.json",
                "Class": "lang-pkgs",
                "Type": "npm",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-23337",
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.19",
                        "FixedVersion": "4.17.21",
                        "Severity": "HIGH",
                        "Title": "Command Injection in lodash",
                        "Description": "lodash versions prior to 4.17.21 are vulnerable to Command Injection.",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-23337"
                    }
                ]
            }
        ]
    }


@pytest.fixture
def sample_trivy_misconfig_output():
    """Sample Trivy JSON output with an IaC misconfiguration result."""
    return {
        "SchemaVersion": 2,
        "ArtifactName": ".",
        "ArtifactType": "filesystem",
        "Results": [
            {
                "Target": "Dockerfile",
                "Class": "config",
                "Type": "dockerfile",
                "Misconfigurations": [
                    {
                        "ID": "DS002",
                        "AVDID": "AVD-DS-0002",
                        "Title": "Image user should not be 'root'",
                        "Description": "Running containers with 'root' user can lead to a container escape situation.",
                        "Resolution": "Add 'USER <non root user name>' line to the Dockerfile",
                        "Severity": "HIGH",
                        "References": ["https://avd.aquasec.com/misconfig/ds002"],
                        "CauseMetadata": {"Provider": "Dockerfile", "StartLine": 1, "EndLine": 12},
                    }
                ],
            }
        ],
    }




@pytest.fixture
def mock_env_vars(monkeypatch):
    """Set up mock environment variables for testing."""
    test_env = {
        'OPENAI_API_KEY': 'test-key-123',
        'AI_PROVIDER': 'openai',
        'APPSEC_SCAN_LEVEL': 'critical-high',
        'APPSEC_CODE_QUALITY': 'true',
        'APPSEC_DEBUG': 'false',
        'APPSEC_AUTO_FIX': 'false',
        'SEMGREP_BIN': 'semgrep',
        'GITLEAKS_BIN': 'gitleaks',
        'TRIVY_BIN': 'trivy'
    }

    for key, value in test_env.items():
        monkeypatch.setenv(key, value)

    return test_env



@pytest.fixture
def output_dir(temp_dir):
    """Create a temporary output directory."""
    output_path = temp_dir / "outputs" / "raw"
    output_path.mkdir(parents=True)
    return output_path








# Performance fixtures for benchmarking
