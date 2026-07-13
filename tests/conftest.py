"""
Shared pytest fixtures and configuration for the AppSec Galaxy test suite.

This module provides reusable fixtures for testing security scanners,
validation functions, and other AppSec Galaxy components.
"""

import pytest
import tempfile
import shutil
import json
from pathlib import Path
from unittest.mock import Mock
import subprocess

# Import exceptions for testing


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
def mock_repo_no_git(temp_dir):
    """Create a directory without .git for testing non-git scenarios."""
    repo_path = temp_dir / "no_git_repo"
    repo_path.mkdir()

    (repo_path / "test.py").write_text("print('hello')")

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
def mock_subprocess_success():
    """Mock successful subprocess.run call."""
    mock_result = Mock()
    mock_result.returncode = 0
    mock_result.stdout = ""
    mock_result.stderr = ""
    return mock_result


@pytest.fixture
def mock_subprocess_failure():
    """Mock failed subprocess.run call."""
    mock_result = Mock()
    mock_result.returncode = 1
    mock_result.stdout = ""
    mock_result.stderr = "Error: Command failed"
    return mock_result


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
def mock_logger():
    """Create a mock logger for testing."""
    return Mock()


@pytest.fixture
def output_dir(temp_dir):
    """Create a temporary output directory."""
    output_path = temp_dir / "outputs" / "raw"
    output_path.mkdir(parents=True)
    return output_path


@pytest.fixture
def dangerous_path_samples():
    """Sample dangerous paths for security testing."""
    return [
        "../../../etc/passwd",  # Path traversal
        "test; rm -rf /",  # Command injection
        "test | cat /etc/passwd",  # Pipe injection
        "test && malicious_command",  # Command chaining
        "test$(whoami)",  # Command substitution
        "test${PATH}",  # Variable substitution
        "test\x00null",  # Null byte injection
        "test\nmalicious",  # Newline injection
        "test`whoami`",  # Backtick command substitution
    ]


@pytest.fixture
def valid_repo_paths(temp_dir):
    """Valid repository paths for positive testing."""
    paths = []
    for i in range(3):
        path = temp_dir / f"valid_repo_{i}"
        path.mkdir()
        (path / ".git").mkdir()
        paths.append(path)
    return paths


@pytest.fixture
def mock_semgrep_binary(monkeypatch):
    """Mock semgrep binary availability."""
    def mock_run(*args, **kwargs):
        result = Mock()
        result.returncode = 0
        result.stdout = json.dumps({"results": [], "errors": []})
        result.stderr = ""
        return result

    monkeypatch.setattr(subprocess, 'run', mock_run)


@pytest.fixture
def mock_gitleaks_binary(monkeypatch):
    """Mock gitleaks binary availability."""
    def mock_run(*args, **kwargs):
        result = Mock()
        result.returncode = 0
        result.stdout = ""
        result.stderr = ""
        return result

    monkeypatch.setattr(subprocess, 'run', mock_run)


@pytest.fixture
def mock_trivy_binary(monkeypatch):
    """Mock trivy binary availability."""
    def mock_run(*args, **kwargs):
        result = Mock()
        result.returncode = 0
        result.stdout = json.dumps({"Results": []})
        result.stderr = ""
        return result

    monkeypatch.setattr(subprocess, 'run', mock_run)


@pytest.fixture(autouse=True)
def reset_logging():
    """Reset logging configuration between tests."""
    import logging
    logging.getLogger().handlers = []
    yield
    logging.getLogger().handlers = []


@pytest.fixture
def sample_findings():
    """Sample security findings for testing report generation."""
    return {
        'semgrep': [
            {
                'check_id': 'sql-injection',
                'path': 'app.py',
                'line': 10,
                'message': 'SQL injection vulnerability',
                'severity': 'ERROR',
                'category': 'security'
            }
        ],
        'gitleaks': [
            {
                'Description': 'API Key',
                'File': 'config.js',
                'Secret': 'sk-***',
                'category': 'security'
            }
        ],
        'trivy': [
            {
                'VulnerabilityID': 'CVE-2021-12345',
                'PkgName': 'lodash',
                'Severity': 'HIGH',
                'FixedVersion': '4.17.21'
            }
        ]
    }


# Performance fixtures for benchmarking
@pytest.fixture
def benchmark_repo(temp_dir):
    """Create a larger repository for performance testing."""
    repo_path = temp_dir / "benchmark_repo"
    repo_path.mkdir()
    (repo_path / ".git").mkdir()

    # Create multiple files to simulate a real project
    for i in range(50):
        file_path = repo_path / f"module_{i}.py"
        file_path.write_text(f"""
def function_{i}(param):
    # Potential vulnerability
    result = eval(param)
    return result

class Class_{i}:
    def method(self):
        password = "hardcoded_{i}"
        return password
""")

    return repo_path
