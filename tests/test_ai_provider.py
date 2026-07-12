"""Provider contracts for AppSec Galaxy's shared AI scanner layer.

OpenAI is the default provider; Anthropic is opt-in via AI_PROVIDER=anthropic.
These tests pin the provider-resolution, client-construction, call, retry,
and connection-test contracts for both providers.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from appsec_galaxy.scanners import ai_scanner


@pytest.fixture(autouse=True)
def isolated_provider(monkeypatch):
    for name in (
        "AI_PROVIDER",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AI_MODEL",
        "APPSEC_AI_SCAN_MODEL",
        "CLAUDE_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "INFERENCE_PROFILE_ID",
    ):
        monkeypatch.delenv(name, raising=False)
    ai_scanner.reset_ai_client_cache()
    ai_scanner.reset_scan_token_usage()
    yield
    ai_scanner.reset_ai_client_cache()
    ai_scanner.reset_scan_token_usage()


# ---------------------------------------------------------------------------
# Provider resolution
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("configured", [None, "", "openai", " OPENAI "])
def test_provider_defaults_to_openai(monkeypatch, configured):
    if configured is not None:
        monkeypatch.setenv("AI_PROVIDER", configured)
    assert ai_scanner._get_ai_provider() == "openai"


@pytest.mark.parametrize("configured", ["anthropic", " Anthropic "])
def test_provider_accepts_anthropic(monkeypatch, configured):
    monkeypatch.setenv("AI_PROVIDER", configured)
    assert ai_scanner._get_ai_provider() == "anthropic"


@pytest.mark.parametrize(
    "configured",
    ["cla" + "ude", "aws_" + "bed" + "rock", "bed" + "rock", "gem" + "ini", "azure"],
)
def test_unknown_provider_is_rejected(monkeypatch, configured):
    monkeypatch.setenv("AI_PROVIDER", configured)
    with pytest.raises(ValueError, match="AI_PROVIDER must be one of openai, anthropic"):
        ai_scanner._get_ai_provider()


# ---------------------------------------------------------------------------
# Model resolution
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("depth", "expected"),
    [
        ("quick", "gpt-5.6-luna"),
        ("standard", "gpt-5.6-terra"),
        ("deep", "gpt-5.6-sol"),
        ("unknown", "gpt-5.6-terra"),
    ],
)
def test_openai_depth_model_defaults(depth, expected):
    assert ai_scanner._get_model_id(depth) == expected


@pytest.mark.parametrize(
    ("depth", "expected"),
    [
        ("quick", "claude-haiku-4-5"),
        ("standard", "claude-sonnet-5"),
        ("deep", "claude-opus-4-8"),
        ("unknown", "claude-sonnet-5"),
    ],
)
def test_anthropic_depth_model_defaults(monkeypatch, depth, expected):
    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    assert ai_scanner._get_model_id(depth) == expected


def test_model_override_precedence(monkeypatch):
    monkeypatch.setenv("AI_MODEL", "user-model")
    assert ai_scanner._get_model_id("deep") == "user-model"
    monkeypatch.setenv("APPSEC_AI_SCAN_MODEL", "scan-model")
    assert ai_scanner._get_model_id("deep") == "scan-model"


def test_get_default_model_ignores_env_overrides(monkeypatch):
    monkeypatch.setenv("AI_MODEL", "user-model")
    assert ai_scanner.get_default_model("openai") == "gpt-5.6-terra"
    assert ai_scanner.get_default_model("anthropic") == "claude-sonnet-5"
    assert ai_scanner.get_default_model("anthropic", "deep") == "claude-opus-4-8"


def test_depth_pricing_follows_provider(monkeypatch):
    assert ai_scanner.get_depth_pricing("deep") == ai_scanner.MODEL_PRICING["openai"]["deep"]
    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    assert ai_scanner.get_depth_pricing("deep") == ai_scanner.MODEL_PRICING["anthropic"]["deep"]
    assert (
        ai_scanner.get_depth_pricing("unknown")
        == ai_scanner.MODEL_PRICING["anthropic"]["standard"]
    )


# ---------------------------------------------------------------------------
# API key requirements
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("api_key", [None, "", "   "])
def test_client_requires_openai_api_key(monkeypatch, api_key):
    if api_key is not None:
        monkeypatch.setenv("OPENAI_API_KEY", api_key)
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        ai_scanner._get_ai_client()


@pytest.mark.parametrize("api_key", [None, "", "   "])
def test_client_requires_anthropic_api_key(monkeypatch, api_key):
    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    if api_key is not None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", api_key)
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        ai_scanner._get_ai_client()


def test_missing_key_error_is_actionable(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    with pytest.raises(ValueError) as excinfo:
        ai_scanner._get_ai_client()
    message = str(excinfo.value)
    assert "ANTHROPIC_API_KEY is not set" in message
    assert "env.example" in message


@pytest.mark.parametrize(
    ("provider", "key_env", "placeholder"),
    [
        ("openai", "OPENAI_API_KEY", "your-openai-api-key-here"),
        ("anthropic", "ANTHROPIC_API_KEY", "your-anthropic-api-key-here"),
    ],
)
def test_placeholder_key_counts_as_unset(monkeypatch, provider, key_env, placeholder):
    monkeypatch.setenv("AI_PROVIDER", provider)
    monkeypatch.setenv(key_env, placeholder)

    assert ai_scanner.api_key_present(provider) is False
    with pytest.raises(ValueError, match="env.example placeholder"):
        ai_scanner._get_ai_client()


def test_real_key_counts_as_present(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key-value")
    assert ai_scanner.api_key_present("openai") is True
    assert ai_scanner.api_key_present("anthropic") is False


# ---------------------------------------------------------------------------
# Client construction and caching
# ---------------------------------------------------------------------------

def test_openai_client_constructor_and_cache(monkeypatch):
    import openai

    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    sdk_client = object()
    constructor = Mock(return_value=sdk_client)
    monkeypatch.setattr(openai, "OpenAI", constructor)

    first = ai_scanner._get_ai_client()
    second = ai_scanner._get_ai_client()

    assert first is second
    assert first.provider == "openai"
    assert first.client is sdk_client
    constructor.assert_called_once_with(
        api_key="test-openai-key",
        timeout=120.0,
        max_retries=0,
    )


def test_anthropic_client_constructor_and_cache(monkeypatch):
    import anthropic

    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
    sdk_client = object()
    constructor = Mock(return_value=sdk_client)
    monkeypatch.setattr(anthropic, "Anthropic", constructor)

    first = ai_scanner._get_ai_client()
    second = ai_scanner._get_ai_client()

    assert first is second
    assert first.provider == "anthropic"
    assert first.client is sdk_client
    constructor.assert_called_once_with(
        api_key="test-anthropic-key",
        timeout=120.0,
        max_retries=0,
    )


def test_provider_switch_rebuilds_cached_client(monkeypatch):
    import anthropic
    import openai

    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
    monkeypatch.setattr(openai, "OpenAI", Mock(return_value=object()))
    monkeypatch.setattr(anthropic, "Anthropic", Mock(return_value=object()))

    first = ai_scanner._get_ai_client()
    assert first.provider == "openai"

    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    second = ai_scanner._get_ai_client()
    assert second.provider == "anthropic"
    assert second is not first


# ---------------------------------------------------------------------------
# OpenAI call contract
# ---------------------------------------------------------------------------

def _wrapped_openai_client(response_or_error):
    create = Mock()
    if isinstance(response_or_error, BaseException):
        create.side_effect = response_or_error
    elif isinstance(response_or_error, list):
        create.side_effect = response_or_error
    else:
        create.return_value = response_or_error
    client = SimpleNamespace(responses=SimpleNamespace(create=create))
    return ai_scanner._AIClient("openai", client), create


def _wrapped_anthropic_client(response_or_error):
    create = Mock()
    if isinstance(response_or_error, BaseException):
        create.side_effect = response_or_error
    elif isinstance(response_or_error, list):
        create.side_effect = response_or_error
    else:
        create.return_value = response_or_error
    client = SimpleNamespace(messages=SimpleNamespace(create=create))
    return ai_scanner._AIClient("anthropic", client), create


def test_openai_request_output_and_usage_are_recorded():
    response = SimpleNamespace(
        output_text="  confirmed finding  ",
        usage=SimpleNamespace(
            input_tokens=120,
            output_tokens=30,
            input_tokens_details=SimpleNamespace(cached_tokens=40),
        ),
    )
    wrapped, create = _wrapped_openai_client(response)

    result = ai_scanner._call_ai(wrapped, "gpt-5.6-terra", "developer rules", "untrusted code", 512)

    assert result == "confirmed finding"
    create.assert_called_once_with(
        model="gpt-5.6-terra",
        instructions="developer rules",
        input="untrusted code",
        max_output_tokens=512,
    )
    assert ai_scanner.get_scan_token_usage() == {
        "input_tokens": 120,
        "output_tokens": 30,
        "cache_read_tokens": 40,
    }


def test_openai_missing_usage_details_are_zero():
    response = SimpleNamespace(output_text="ok", usage=None)
    wrapped, _ = _wrapped_openai_client(response)
    assert ai_scanner._call_ai(wrapped, "model", "rules", "input", 64) == "ok"
    assert ai_scanner.get_scan_token_usage() == {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
    }


# ---------------------------------------------------------------------------
# Anthropic call contract
# ---------------------------------------------------------------------------

def test_anthropic_request_output_and_usage_are_recorded():
    response = SimpleNamespace(
        content=[
            SimpleNamespace(type="thinking", thinking="..."),
            SimpleNamespace(type="text", text="  confirmed "),
            SimpleNamespace(type="text", text="finding  "),
        ],
        usage=SimpleNamespace(
            input_tokens=200,
            output_tokens=50,
            cache_read_input_tokens=80,
        ),
    )
    wrapped, create = _wrapped_anthropic_client(response)

    result = ai_scanner._call_ai(
        wrapped, "claude-sonnet-5", "developer rules", "untrusted code", 512
    )

    assert result == "confirmed finding"
    create.assert_called_once_with(
        model="claude-sonnet-5",
        max_tokens=512,
        system="developer rules",
        messages=[{"role": "user", "content": "untrusted code"}],
    )
    assert ai_scanner.get_scan_token_usage() == {
        "input_tokens": 200,
        "output_tokens": 50,
        "cache_read_tokens": 80,
    }


def test_openai_truncated_response_logs_actionable_warning(caplog):
    # Regression: a findings array longer than max_output_tokens comes back
    # as unterminated JSON and the whole batch is lost. The truncation must
    # at least be named in the logs with the knobs that fix it.
    response = SimpleNamespace(
        output_text='[{"file": "app.js", "line": 1, "sev',
        usage=SimpleNamespace(input_tokens=10, output_tokens=4096, input_tokens_details=None),
        status='incomplete',
        incomplete_details=SimpleNamespace(reason='max_output_tokens'),
    )
    wrapped, _ = _wrapped_openai_client(response)

    with caplog.at_level('WARNING'):
        ai_scanner._call_ai(wrapped, "model", "rules", "input", 64)

    assert 'truncated' in caplog.text
    assert 'DEPTH_MAX_TOKENS' in caplog.text


def test_anthropic_truncated_response_logs_actionable_warning(caplog):
    response = SimpleNamespace(
        content=[SimpleNamespace(type="text", text='[{"file": "app.js"')],
        usage=None,
        stop_reason='max_tokens',
    )
    wrapped, _ = _wrapped_anthropic_client(response)

    with caplog.at_level('WARNING'):
        ai_scanner._call_ai(wrapped, "model", "rules", "input", 64)

    assert 'truncated' in caplog.text
    assert 'DEPTH_MAX_TOKENS' in caplog.text


def test_depth_max_tokens_sized_for_vulnerable_repos():
    # Regression guard for the nodejs-goof truncation: 4096 was too small
    # for one batch of findings from a deliberately vulnerable app.
    assert ai_scanner.DEPTH_MAX_TOKENS['quick'] >= 8192
    assert ai_scanner.DEPTH_MAX_TOKENS['standard'] >= 16384
    assert ai_scanner.DEPTH_MAX_TOKENS['deep'] >= 16384


def test_anthropic_missing_usage_and_content_are_safe():
    response = SimpleNamespace(content=None, usage=None)
    wrapped, _ = _wrapped_anthropic_client(response)
    assert ai_scanner._call_ai(wrapped, "model", "rules", "input", 64) == ""
    assert ai_scanner.get_scan_token_usage() == {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_tokens": 0,
    }


# ---------------------------------------------------------------------------
# Retry behavior (shared across providers)
# ---------------------------------------------------------------------------

def test_retryable_error_retries_then_succeeds(monkeypatch):
    class RateLimitError(Exception):
        pass

    response = SimpleNamespace(output_text="ok", usage=None)
    wrapped, create = _wrapped_openai_client([RateLimitError("limited"), response])
    sleep = Mock()
    monkeypatch.setattr(ai_scanner.time, "sleep", sleep)

    assert ai_scanner._call_ai(wrapped, "model", "rules", "input", 64) == "ok"
    assert create.call_count == 2
    sleep.assert_called_once_with(2)


def test_anthropic_overloaded_error_is_retried(monkeypatch):
    class OverloadedError(Exception):
        status_code = 529

    response = SimpleNamespace(
        content=[SimpleNamespace(type="text", text="ok")], usage=None
    )
    wrapped, create = _wrapped_anthropic_client([OverloadedError("busy"), response])
    sleep = Mock()
    monkeypatch.setattr(ai_scanner.time, "sleep", sleep)

    assert ai_scanner._call_ai(wrapped, "model", "rules", "input", 64) == "ok"
    assert create.call_count == 2
    sleep.assert_called_once_with(2)


def test_nonretryable_error_fails_immediately(monkeypatch):
    wrapped, create = _wrapped_openai_client(ValueError("invalid request"))
    sleep = Mock()
    monkeypatch.setattr(ai_scanner.time, "sleep", sleep)
    with pytest.raises(ValueError, match="invalid request"):
        ai_scanner._call_ai(wrapped, "model", "rules", "input", 64)
    assert create.call_count == 1
    sleep.assert_not_called()


def test_retryable_error_stops_after_three_attempts(monkeypatch):
    class ServerError(Exception):
        status_code = 503

    error = ServerError("unavailable")
    wrapped, create = _wrapped_openai_client(error)
    sleep = Mock()
    monkeypatch.setattr(ai_scanner.time, "sleep", sleep)
    with pytest.raises(ServerError, match="unavailable"):
        ai_scanner._call_ai(wrapped, "model", "rules", "input", 64)
    assert create.call_count == 3
    assert sleep.call_args_list == [((2,),), ((3,),)]


# ---------------------------------------------------------------------------
# Connection test
# ---------------------------------------------------------------------------

def test_connection_test_reports_missing_key():
    ok, message = ai_scanner.test_ai_connection()
    assert ok is False
    assert "OPENAI_API_KEY is not set" in message


def test_connection_test_reports_invalid_provider(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "gem" + "ini")
    ok, message = ai_scanner.test_ai_connection()
    assert ok is False
    assert "AI_PROVIDER must be one of" in message


def test_connection_test_success(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(
        ai_scanner, "_get_ai_client", lambda: ai_scanner._AIClient("openai", object())
    )
    monkeypatch.setattr(ai_scanner, "_call_ai", lambda *args: "ok")

    ok, message = ai_scanner.test_ai_connection()

    assert ok is True
    assert "openai connection OK" in message
    assert "gpt-5.6-luna" in message


def test_connection_test_classifies_auth_failure(monkeypatch):
    class AuthenticationError(Exception):
        status_code = 401

    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "bad-key")
    monkeypatch.setattr(
        ai_scanner, "_get_ai_client", lambda: ai_scanner._AIClient("anthropic", object())
    )

    def raise_auth(*args):
        raise AuthenticationError("401 invalid x-api-key")

    monkeypatch.setattr(ai_scanner, "_call_ai", raise_auth)

    ok, message = ai_scanner.test_ai_connection()

    assert ok is False
    assert "rejected the API key" in message
    assert "ANTHROPIC_API_KEY" in message
    assert "bad-key" not in message


def test_connection_test_classifies_network_failure(monkeypatch):
    class APIConnectionError(Exception):
        pass

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(
        ai_scanner, "_get_ai_client", lambda: ai_scanner._AIClient("openai", object())
    )

    def raise_conn(*args):
        raise APIConnectionError("Connection error.")

    monkeypatch.setattr(ai_scanner, "_call_ai", raise_conn)

    ok, message = ai_scanner.test_ai_connection()

    assert ok is False
    assert "network error" in message


def test_connection_test_classifies_unknown_model(monkeypatch):
    class NotFoundError(Exception):
        status_code = 404

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("AI_MODEL", "not-a-model")
    monkeypatch.setattr(
        ai_scanner, "_get_ai_client", lambda: ai_scanner._AIClient("openai", object())
    )

    def raise_missing(*args):
        raise NotFoundError("model not found")

    monkeypatch.setattr(ai_scanner, "_call_ai", raise_missing)

    ok, message = ai_scanner.test_ai_connection()

    assert ok is False
    assert "not-a-model" in message


# ---------------------------------------------------------------------------
# Misc invariants
# ---------------------------------------------------------------------------

def test_native_scanner_uses_only_shared_ai_helpers():
    source = inspect.getsource(ai_scanner)
    assert "_get_" + "bed" + "rock_client" not in source
    assert "_call_" + "bed" + "rock" not in source
    assert "invoke_model" not in source


def test_malformed_verification_response_preserves_original_findings(monkeypatch):
    original = [{
        "path": "app.py",
        "start": {"line": 1},
        "ai_vulnerability_type": "Injection",
        "ai_title": "Unsafe input",
        "ai_confidence": 0.9,
        "extra": {"metadata": {"confidence": 0.9}},
    }]
    monkeypatch.setattr(ai_scanner, "_call_ai", lambda *args: "not-json")

    result = ai_scanner._run_verification_pass(
        object(),
        "gpt-5.6-terra",
        original,
        [{"path": "app.py", "content": "unsafe(value)"}],
        512,
    )

    assert result is original
