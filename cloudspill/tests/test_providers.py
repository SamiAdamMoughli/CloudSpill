"""Tests for LLM provider implementations and the make_provider factory."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from cloudspill.enrichers.ai import AIEnricher
from cloudspill.enrichers.providers import make_provider
from cloudspill.enrichers.providers.base import LLMProvider
from cloudspill.enrichers.providers.openai_compat import OpenAICompatProvider
from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph


def _make_finding() -> Finding:
    return Finding(
        rule_id="S3-001",
        severity=Severity.CRITICAL,
        title="Bucket publicly readable",
        description="ACL is public-read.",
        resource="aws_s3_bucket.test",
        file="test.tf",
        line=1,
    )


# ── LLMProvider structural check ─────────────────────────────────────────────


class TestLLMProviderProtocol:
    def test_openai_compat_satisfies_protocol(self) -> None:
        provider = OpenAICompatProvider()
        assert isinstance(provider, LLMProvider)

    def test_concrete_class_satisfies_protocol(self) -> None:
        class _Stub:
            def complete(self, system: str, user: str) -> str:
                return "ok"

        assert isinstance(_Stub(), LLMProvider)


# ── OpenAICompatProvider ──────────────────────────────────────────────────────


class TestOpenAICompatProvider:
    def _mock_response(self, content: str) -> MagicMock:
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {
            "choices": [{"message": {"content": content}}]
        }
        return resp

    def test_returns_content_string(self) -> None:
        provider = OpenAICompatProvider()
        response = self._mock_response("hello from model")
        with patch("httpx.Client") as mock_client:
            inner = MagicMock(post=MagicMock(return_value=response))
            mock_client.return_value.__enter__ = MagicMock(return_value=inner)
            mock_client.return_value.__exit__ = MagicMock(return_value=False)
            result = provider.complete("system", "user")
        assert result == "hello from model"

    def test_posts_to_correct_url(self) -> None:
        provider = OpenAICompatProvider(base_url="http://my-server/v1")
        response = self._mock_response("ok")
        with patch("httpx.Client") as mock_client:
            inner = MagicMock(post=MagicMock(return_value=response))
            mock_client.return_value.__enter__ = MagicMock(return_value=inner)
            mock_client.return_value.__exit__ = MagicMock(return_value=False)
            provider.complete("sys", "usr")
            inner.post.assert_called_once()
            url = inner.post.call_args[0][0]
        assert "my-server" in url
        assert url.endswith("/chat/completions")

    def test_sends_model_in_payload(self) -> None:
        provider = OpenAICompatProvider(model="my-custom-model")
        response = self._mock_response("ok")
        with patch("httpx.Client") as mock_client:
            inner = MagicMock(post=MagicMock(return_value=response))
            mock_client.return_value.__enter__ = MagicMock(return_value=inner)
            mock_client.return_value.__exit__ = MagicMock(return_value=False)
            provider.complete("sys", "usr")
            payload = inner.post.call_args[1]["json"]
        assert payload["model"] == "my-custom-model"

    def test_sends_system_and_user_messages(self) -> None:
        provider = OpenAICompatProvider()
        response = self._mock_response("ok")
        with patch("httpx.Client") as mock_client:
            inner = MagicMock(post=MagicMock(return_value=response))
            mock_client.return_value.__enter__ = MagicMock(return_value=inner)
            mock_client.return_value.__exit__ = MagicMock(return_value=False)
            provider.complete("my system prompt", "my user message")
            payload = inner.post.call_args[1]["json"]
        roles = [m["role"] for m in payload["messages"]]
        contents = [m["content"] for m in payload["messages"]]
        assert roles == ["system", "user"]
        assert "my system prompt" in contents
        assert "my user message" in contents

    def test_raises_on_http_error(self) -> None:
        import httpx
        provider = OpenAICompatProvider()
        with patch("httpx.Client") as mock_client:
            inner = MagicMock()
            inner.post.side_effect = httpx.ConnectError("refused")
            mock_client.return_value.__enter__ = MagicMock(return_value=inner)
            mock_client.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(httpx.ConnectError):
                provider.complete("sys", "usr")

    def test_base_url_normalised(self) -> None:
        provider = OpenAICompatProvider(base_url="http://localhost:11434/v1/")
        assert provider.base_url.endswith("/chat/completions")
        assert "/v1//" not in provider.base_url


# ── OpenAIProvider (SDK mocked) ───────────────────────────────────────────────


class TestOpenAIProvider:
    def _make_sdk_response(self, text: str) -> MagicMock:
        msg = MagicMock()
        msg.content = text
        choice = MagicMock()
        choice.message = msg
        resp = MagicMock()
        resp.choices = [choice]
        return resp

    def test_complete_returns_content(self) -> None:
        fake_openai = MagicMock()
        fake_openai.OpenAI.return_value.chat.completions.create.return_value = (
            self._make_sdk_response("openai response")
        )
        with patch.dict("sys.modules", {"openai": fake_openai}):
            from importlib import reload
            import cloudspill.enrichers.providers.openai as mod
            reload(mod)
            provider = mod.OpenAIProvider(api_key="sk-test", model="gpt-4o")
            result = provider.complete("system", "user")
        assert result == "openai response"

    def test_raises_import_error_without_sdk(self) -> None:
        with patch.dict("sys.modules", {"openai": None}):  # type: ignore[dict-item]
            from importlib import reload
            import cloudspill.enrichers.providers.openai as mod
            reload(mod)
            with pytest.raises(ImportError, match="openai package"):
                mod.OpenAIProvider(api_key="sk-test")

    def test_passes_model_to_sdk(self) -> None:
        fake_openai = MagicMock()
        create = fake_openai.OpenAI.return_value.chat.completions.create
        create.return_value = self._make_sdk_response("ok")
        with patch.dict("sys.modules", {"openai": fake_openai}):
            from importlib import reload
            import cloudspill.enrichers.providers.openai as mod
            reload(mod)
            provider = mod.OpenAIProvider(api_key="sk-test", model="gpt-4o-mini")
            provider.complete("sys", "usr")
        call_kwargs = create.call_args[1]
        assert call_kwargs["model"] == "gpt-4o-mini"


# ── AnthropicProvider (SDK mocked) ────────────────────────────────────────────


class TestAnthropicProvider:
    def _make_sdk_response(self, text: str) -> MagicMock:
        block = MagicMock()
        block.text = text
        resp = MagicMock()
        resp.content = [block]
        return resp

    def test_complete_returns_content(self) -> None:
        fake_anthropic = MagicMock()
        fake_anthropic.Anthropic.return_value.messages.create.return_value = (
            self._make_sdk_response("claude response")
        )
        with patch.dict("sys.modules", {"anthropic": fake_anthropic}):
            from importlib import reload
            import cloudspill.enrichers.providers.anthropic as mod
            reload(mod)
            provider = mod.AnthropicProvider(api_key="sk-ant-test")
            result = provider.complete("system", "user")
        assert result == "claude response"

    def test_raises_import_error_without_sdk(self) -> None:
        with patch.dict("sys.modules", {"anthropic": None}):  # type: ignore[dict-item]
            from importlib import reload
            import cloudspill.enrichers.providers.anthropic as mod
            reload(mod)
            with pytest.raises(ImportError, match="anthropic package"):
                mod.AnthropicProvider(api_key="sk-ant-test")

    def test_passes_model_to_sdk(self) -> None:
        fake_anthropic = MagicMock()
        create = fake_anthropic.Anthropic.return_value.messages.create
        create.return_value = self._make_sdk_response("ok")
        with patch.dict("sys.modules", {"anthropic": fake_anthropic}):
            from importlib import reload
            import cloudspill.enrichers.providers.anthropic as mod
            reload(mod)
            provider = mod.AnthropicProvider(
                api_key="sk-ant-test", model="claude-haiku-4-5-20251001"
            )
            provider.complete("sys", "usr")
        call_kwargs = create.call_args[1]
        assert call_kwargs["model"] == "claude-haiku-4-5-20251001"

    def test_system_passed_as_top_level_param(self) -> None:
        """Anthropic API takes system as a top-level param, not in messages."""
        fake_anthropic = MagicMock()
        create = fake_anthropic.Anthropic.return_value.messages.create
        create.return_value = self._make_sdk_response("ok")
        with patch.dict("sys.modules", {"anthropic": fake_anthropic}):
            from importlib import reload
            import cloudspill.enrichers.providers.anthropic as mod
            reload(mod)
            provider = mod.AnthropicProvider(api_key="sk-ant-test")
            provider.complete("my system", "my user message")
        call_kwargs = create.call_args[1]
        assert call_kwargs["system"] == "my system"
        assert call_kwargs["messages"] == [{"role": "user", "content": "my user message"}]


# ── make_provider factory ─────────────────────────────────────────────────────


class TestMakeProvider:
    def test_local_returns_openai_compat(self) -> None:
        provider = make_provider("local", model="qwen3.6-35b-a3b")
        assert isinstance(provider, OpenAICompatProvider)

    def test_local_default(self) -> None:
        provider = make_provider("local", model="any-model")
        assert isinstance(provider, LLMProvider)

    def test_openai_requires_api_key(self) -> None:
        with pytest.raises(ValueError, match="api-key"):
            make_provider("openai", model="gpt-4o", api_key=None)

    def test_anthropic_requires_api_key(self) -> None:
        with pytest.raises(ValueError, match="api-key"):
            make_provider("anthropic", model="claude-haiku-4-5-20251001", api_key=None)

    def test_unknown_provider_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown provider"):
            make_provider("grok", model="grok-1")

    def test_local_passes_base_url(self) -> None:
        provider = make_provider(
            "local", model="x", base_url="http://gpu:8000/v1"
        )
        assert isinstance(provider, OpenAICompatProvider)
        assert "gpu:8000" in provider.base_url


# ── AIEnricher + custom provider ─────────────────────────────────────────────


class TestAIEnricherWithProvider:
    def _make_provider(self, response_json: str) -> MagicMock:
        mock = MagicMock(spec=["complete"])
        mock.complete.return_value = response_json
        return mock

    def test_accepts_custom_provider(self) -> None:
        payload = '{"explanation": "risk here", "fix": "fix here", "confidence": 0.9}'
        provider = self._make_provider(payload)
        enricher = AIEnricher(provider=provider)
        results = enricher.enrich([_make_finding()], [], ResourceGraph())
        assert results[0].explanation == "risk here"
        assert results[0].remediation_patch == "fix here"
        assert results[0].confidence == 0.9

    def test_provider_called_with_system_and_user(self) -> None:
        provider = self._make_provider('{"explanation":"x","fix":"y","confidence":1.0}')
        enricher = AIEnricher(provider=provider)
        enricher.enrich([_make_finding()], [], ResourceGraph())
        call_args = provider.complete.call_args
        system_arg, user_arg = call_args[0]
        assert "security expert" in system_arg.lower()
        assert "S3-001" in user_arg

    def test_graceful_fallback_when_provider_raises(self) -> None:
        provider = MagicMock(spec=["complete"])
        provider.complete.side_effect = RuntimeError("model crashed")
        enricher = AIEnricher(provider=provider)
        results = enricher.enrich([_make_finding()], [], ResourceGraph())
        assert len(results) == 1
        assert "unavailable" in results[0].explanation.lower()
        assert results[0].confidence == 0.0

    def test_default_provider_is_openai_compat(self) -> None:
        enricher = AIEnricher()
        # Default provider wraps OpenAICompatProvider — offline call returns unavailable
        results = enricher.enrich([_make_finding()], [], ResourceGraph())
        assert len(results) == 1
        assert "unavailable" in results[0].explanation.lower()

    def test_provider_called_once_per_finding(self) -> None:
        provider = self._make_provider('{"explanation":"x","fix":"y","confidence":1.0}')
        enricher = AIEnricher(provider=provider)
        findings = [_make_finding(), _make_finding()]
        enricher.enrich(findings, [], ResourceGraph())
        assert provider.complete.call_count == 2
