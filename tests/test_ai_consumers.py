"""AI consumer contracts for remediation and application wiring.

OpenAI is the default provider; Anthropic is supported via
AI_PROVIDER=anthropic. These tests pin the consumer-facing behavior:
model selection, provider validation, environment validation, and
manifest/example contracts.
"""

from pathlib import Path
from types import SimpleNamespace
import tomllib

import pytest

from appsec_galaxy.auto_remediation import remediation
from appsec_galaxy.main import validate_environment_config


@pytest.fixture(autouse=True)
def clean_ai_environment(monkeypatch):
    for name in (
        "AI_PROVIDER",
        "AI_MODEL",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "APPSEC_AI_SCAN",
        "APPSEC_AUTO_FIX",
        "APPSEC_AUTO_FIX_MODE",
    ):
        monkeypatch.delenv(name, raising=False)


def _shared_client(monkeypatch, provider="openai"):
    wrapped = SimpleNamespace(provider=provider, client=object())
    monkeypatch.setattr(
        "appsec_galaxy.scanners.ai_scanner._get_ai_client",
        lambda: wrapped,
    )
    return wrapped


@pytest.mark.parametrize(
    ("configured_model", "environment_model", "expected"),
    [
        (None, None, "gpt-5.6-terra"),
        (None, "  gpt-5.6-luna  ", "gpt-5.6-luna"),
        ("gpt-5.6-sol", "gpt-5.6-luna", "gpt-5.6-sol"),
    ],
)
def test_remediator_model_selection(
    monkeypatch, configured_model, environment_model, expected
):
    wrapped = _shared_client(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    if environment_model is not None:
        monkeypatch.setenv("AI_MODEL", environment_model)

    result = remediation.AutoRemediator("openai", model=configured_model)

    assert result.ai_provider == "openai"
    assert result.model == expected
    assert result.client is wrapped


def test_remediator_anthropic_default_model(monkeypatch):
    wrapped = _shared_client(monkeypatch, provider="anthropic")
    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    result = remediation.AutoRemediator("anthropic")

    assert result.ai_provider == "anthropic"
    assert result.model == "claude-sonnet-5"
    assert result.client is wrapped


@pytest.mark.parametrize(
    "provider",
    ["cla" + "ude", "aws_" + "bed" + "rock", "bed" + "rock", "gem" + "ini"],
)
def test_remediator_rejects_unknown_provider(provider):
    with pytest.raises(ValueError, match="AI_PROVIDER must be one of openai, anthropic"):
        remediation.AutoRemediator(provider)


def test_executive_summary_uses_shared_call(monkeypatch):
    wrapped = _shared_client(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    captured = {}

    def fake_call(client, model, instructions, user_input, max_tokens):
        captured.update(
            client=client,
            model=model,
            instructions=instructions,
            user_input=user_input,
            max_tokens=max_tokens,
        )
        return "  Prioritize the critical injection path.  "

    monkeypatch.setattr(remediation, "_call_ai", fake_call, raising=False)
    remediator = remediation.AutoRemediator("openai")

    result = remediator.generate_executive_summary(
        [{"severity": "critical"}, {"severity": "high"}]
    )

    assert result == "Prioritize the critical injection path."
    assert captured["client"] is wrapped
    assert captured["model"] == "gpt-5.6-terra"
    assert "security" in captured["instructions"].lower()
    assert "2 security findings" in captured["user_input"]
    assert captured["max_tokens"] == 300


def test_executive_summary_preserves_static_fallback(monkeypatch):
    _shared_client(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(
        remediation,
        "_call_ai",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("offline")),
        raising=False,
    )

    result = remediation.AutoRemediator("openai").generate_executive_summary(
        [{"severity": "critical"}]
    )

    assert result == (
        "Security scan found 1 findings (1 critical, 0 high severity). "
        "Immediate review recommended."
    )


def test_executive_summary_empty_response_preserves_static_fallback(monkeypatch):
    _shared_client(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(remediation, "_call_ai", lambda *args, **kwargs: "   ")

    result = remediation.AutoRemediator("openai").generate_executive_summary(
        [{"severity": "high"}]
    )

    assert result == (
        "Security scan found 1 findings (0 critical, 1 high severity). "
        "Immediate review recommended."
    )


def test_code_fix_uses_shared_call_and_sanitizes(monkeypatch, tmp_path):
    wrapped = _shared_client(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    source = tmp_path / "app.py"
    source.write_text("before\nunsafe(user_input)\nafter\n", encoding="utf-8")
    captured = {}

    def fake_call(client, model, instructions, user_input, max_tokens):
        captured.update(
            client=client,
            model=model,
            instructions=instructions,
            user_input=user_input,
            max_tokens=max_tokens,
        )
        return "```python\nsafe(user_input)\n```"

    monkeypatch.setattr(remediation, "_call_ai", fake_call, raising=False)
    finding = {
        "tool": "semgrep",
        "path": "app.py",
        "check_id": "python.injection",
        "start": {"line": 2},
        "extra": {"message": "Untrusted input reaches a sink"},
    }

    result = remediation.AutoRemediator("openai").generate_code_fix(
        finding, str(tmp_path)
    )

    assert result["fixed_line"] == "safe(user_input)"
    assert result["original_line"] == "unsafe(user_input)"
    assert captured["client"] is wrapped
    assert captured["model"] == "gpt-5.6-terra"
    assert "single corrected line" in captured["instructions"].lower()
    assert "Untrusted input reaches a sink" in captured["user_input"]
    assert captured["max_tokens"] == 200


def test_code_fix_shared_call_failure_returns_none(monkeypatch, tmp_path):
    _shared_client(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    (tmp_path / "app.py").write_text("unsafe(value)\n", encoding="utf-8")
    monkeypatch.setattr(
        remediation,
        "_call_ai",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("offline")),
        raising=False,
    )

    result = remediation.AutoRemediator("openai").generate_code_fix(
        {
            "tool": "semgrep",
            "path": "app.py",
            "check_id": "python.injection",
            "start": {"line": 1},
            "extra": {"message": "unsafe"},
        },
        str(tmp_path),
    )

    assert result is None


def test_code_fix_preserves_original_indentation(monkeypatch, tmp_path):
    _shared_client(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    (tmp_path / "app.py").write_text(
        "def handler(value):\n    unsafe(value)\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        remediation,
        "_call_ai",
        lambda *args, **kwargs: "safe(value)",
    )

    result = remediation.AutoRemediator("openai").generate_code_fix(
        {
            "tool": "semgrep",
            "path": "app.py",
            "check_id": "python.injection",
            "start": {"line": 2},
            "extra": {"message": "unsafe"},
        },
        str(tmp_path),
    )

    assert result["fixed_line"] == "    safe(value)"


def test_code_fix_rejects_multiline_model_response(monkeypatch, tmp_path):
    _shared_client(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    (tmp_path / "app.py").write_text("unsafe(value)\n", encoding="utf-8")
    monkeypatch.setattr(
        remediation,
        "_call_ai",
        lambda *args, **kwargs: "if attacker_controlled_value:\n    safe(value)",
    )

    result = remediation.AutoRemediator("openai").generate_code_fix(
        {
            "tool": "semgrep",
            "path": "app.py",
            "check_id": "python.injection",
            "start": {"line": 1},
            "extra": {"message": "unsafe"},
        },
        str(tmp_path),
    )

    assert result is None


def test_create_remediation_pr_uses_configured_provider(monkeypatch):
    wrapped = _shared_client(monkeypatch, provider="anthropic")
    captured = {}

    def fake_remediate_dependencies(self, findings, repo_path):
        captured.update(
            provider=self.ai_provider,
            model=self.model,
            client=self.client,
            findings=findings,
            repo_path=repo_path,
        )
        return {"success": True, "successful_fixes": 0}

    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(
        remediation.AutoRemediator,
        "remediate_dependencies",
        fake_remediate_dependencies,
    )

    assert remediation.create_remediation_pr("/tmp/repo", [], "dependencies")
    assert captured == {
        "provider": "anthropic",
        "model": "claude-sonnet-5",
        "client": wrapped,
        "findings": [],
        "repo_path": "/tmp/repo",
    }


def test_create_remediation_pr_openai_model_override(monkeypatch):
    wrapped = _shared_client(monkeypatch)
    captured = {}

    def fake_remediate_dependencies(self, findings, repo_path):
        captured.update(
            provider=self.ai_provider,
            model=self.model,
            client=self.client,
        )
        return {"success": True, "successful_fixes": 0}

    monkeypatch.setenv("AI_MODEL", " gpt-5.6-sol ")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(
        remediation.AutoRemediator,
        "remediate_dependencies",
        fake_remediate_dependencies,
    )

    assert remediation.create_remediation_pr("/tmp/repo", [], "dependencies")
    assert captured == {
        "provider": "openai",
        "model": "gpt-5.6-sol",
        "client": wrapped,
    }


def test_environment_validation_defaults_to_openai_without_ai_key(monkeypatch):
    config = validate_environment_config()

    assert config["ai_provider"] == "openai"
    assert config["ai_api_key"] is False


def test_environment_validation_rejects_unknown_provider(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "bed" + "rock")

    with pytest.raises(ValueError, match="AI_PROVIDER must be one of openai, anthropic"):
        validate_environment_config()


@pytest.mark.parametrize("feature", ["APPSEC_AI_SCAN", "APPSEC_AUTO_FIX"])
def test_environment_validation_requires_openai_key_for_ai_features(monkeypatch, feature):
    monkeypatch.setenv(feature, "true")

    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        validate_environment_config()


def test_environment_validation_rejects_placeholder_key_for_ai_features(monkeypatch):
    monkeypatch.setenv("APPSEC_AI_SCAN", "true")
    monkeypatch.setenv("OPENAI_API_KEY", "your-openai-api-key-here")

    with pytest.raises(ValueError, match="OPENAI_API_KEY is required"):
        validate_environment_config()


def test_environment_validation_placeholder_key_reads_as_absent(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "your-openai-api-key-here")

    config = validate_environment_config()

    assert config["ai_api_key"] is False


@pytest.mark.parametrize("feature", ["APPSEC_AI_SCAN", "APPSEC_AUTO_FIX"])
def test_environment_validation_requires_anthropic_key_when_selected(monkeypatch, feature):
    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    monkeypatch.setenv(feature, "true")

    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        validate_environment_config()


def test_environment_validation_anthropic_key_satisfies_anthropic(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    monkeypatch.setenv("APPSEC_AI_SCAN", "true")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    config = validate_environment_config()

    assert config["ai_provider"] == "anthropic"
    assert config["ai_api_key"] is True


def test_environment_validation_records_presence_without_logging_value(
    monkeypatch, caplog
):
    secret = "test-openai-secret-value"
    monkeypatch.setenv("APPSEC_AI_SCAN", "true")
    monkeypatch.setenv("OPENAI_API_KEY", secret)

    config = validate_environment_config()

    assert config["ai_api_key"] is True
    assert secret not in caplog.text


def test_cli_entrypoint_rejects_invalid_provider_before_menu(monkeypatch):
    from appsec_galaxy import main as main_module

    monkeypatch.setenv("AI_PROVIDER", "bed" + "rock")
    monkeypatch.setattr(
        main_module,
        "show_interactive_menu",
        lambda: pytest.fail("menu opened before validation"),
    )

    with pytest.raises(ValueError, match="AI_PROVIDER must be one of openai, anthropic"):
        main_module.main([])


def test_cli_process_exits_nonzero_for_invalid_required_configuration(monkeypatch):
    import os
    import subprocess
    import sys

    root = Path(__file__).parents[1]
    env = os.environ.copy()
    env.update(
        PYTHONPATH=str(root / "src"),
        PYTHON_DOTENV_DISABLED="1",
        GITHUB_ACTIONS="true",
        APPSEC_AI_SCAN="true",
        AI_PROVIDER="openai",
    )
    env.pop("OPENAI_API_KEY", None)

    result = subprocess.run(
        [sys.executable, "-m", "appsec_galaxy.main"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert result.returncode != 0
    assert "OPENAI_API_KEY is required" in result.stderr


def test_scoped_consumers_have_no_legacy_provider_residue():
    source_root = Path(__file__).parents[1] / "src" / "appsec_galaxy"
    paths = [
        source_root / "auto_remediation" / "remediation.py",
        source_root / "main.py",
        source_root / "ai_cross_file.py",
        source_root / "reporting" / "ai_summary.py",
        source_root / "config.py",
    ]
    banned = (
        "bed" + "rock",
        "boto3",
        "claude" + "_code",
        "claude_api_key",
        "aws_access_key_id",
        "aws_secret_access_key",
        "inference_profile_id",
    )

    for path in paths:
        source = path.read_text(encoding="utf-8").lower()
        for term in banned:
            assert term not in source, f"{term} remains in {path}"


def test_dependencies_and_examples_cover_both_providers():
    root = Path(__file__).parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = project["project"]["dependencies"]
    requirements = (root / "requirements.txt").read_text(encoding="utf-8")
    examples = "\n".join(
        [
            (root / "env.example").read_text(encoding="utf-8"),
            (root / "mcp" / "mcp_env.example").read_text(encoding="utf-8"),
        ]
    )

    assert "openai>=2.0.0,<3.0.0" in dependencies
    assert "openai>=2.0.0,<3.0.0" in requirements
    assert any(dep.startswith("anthropic>=") for dep in dependencies)
    assert "anthropic>=" in requirements
    assert "OPENAI_API_KEY=" in examples
    assert "ANTHROPIC_API_KEY=" in examples
    assert "AI_PROVIDER=openai" in examples

    combined = "\n".join(dependencies) + requirements + examples
    for legacy_name in (
        "boto" + "3",
        "bed" + "rock",
        "gem" + "ini",
    ):
        assert legacy_name not in combined.lower()
