"""LLM provider implementations and factory."""

from __future__ import annotations

from cloudspill.enrichers.providers.anthropic import AnthropicProvider
from cloudspill.enrichers.providers.base import LLMProvider
from cloudspill.enrichers.providers.google import GeminiProvider
from cloudspill.enrichers.providers.openai import OpenAIProvider
from cloudspill.enrichers.providers.openai_compat import OpenAICompatProvider

__all__ = [
    "LLMProvider",
    "OpenAICompatProvider",
    "OpenAIProvider",
    "AnthropicProvider",
    "GeminiProvider",
    "make_provider",
]

_PROVIDER_NAMES = ("local", "openai", "anthropic", "google")


def make_provider(
    name: str,
    *,
    model: str,
    base_url: str = "http://localhost:11434/v1",
    api_key: str | None = None,
    temperature: float = 0.1,
    timeout: int = 30,
) -> LLMProvider:
    """Instantiate the named provider.

    Args:
        name: one of "local", "openai", "anthropic", "google".
        model: model tag.
        base_url: only used for "local".
        api_key: required for "openai", "anthropic", "google".
        temperature: sampling temperature, 0.0–1.0.
        timeout: request timeout in seconds.

    Raises:
        ValueError: unknown provider name or api_key missing for cloud.
        ImportError: SDK package not installed for "openai" / "anthropic".
    """
    if name == "local":
        return OpenAICompatProvider(
            base_url=base_url,
            model=model,
            temperature=temperature,
            timeout=timeout,
        )
    if name == "google":
        if not api_key:
            raise ValueError(
                "--api-key (or CLOUDSPILL_API_KEY env var) is required"
                " for --provider google"
            )
        return GeminiProvider(
            api_key=api_key,
            model=model,
            timeout=timeout,
        )
    if name == "openai":
        if not api_key:
            raise ValueError(
                "--api-key (or CLOUDSPILL_API_KEY env var) is required"
                " for --provider openai"
            )
        return OpenAIProvider(api_key=api_key, model=model, temperature=temperature)
    if name == "anthropic":
        if not api_key:
            raise ValueError(
                "--api-key (or CLOUDSPILL_API_KEY env var) is required"
                " for --provider anthropic"
            )
        return AnthropicProvider(api_key=api_key, model=model, temperature=temperature)
    raise ValueError(
        f"Unknown provider '{name}'." f" Choose from: {', '.join(_PROVIDER_NAMES)}"
    )
