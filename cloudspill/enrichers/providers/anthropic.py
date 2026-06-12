"""AnthropicProvider — Claude models via the official anthropic SDK.

Install the optional dependency before use:
    pip install "cloudspill[ai]"   # installs openai + anthropic
    pip install anthropic>=0.30    # or just anthropic
"""

from __future__ import annotations

from typing import Any


class AnthropicProvider:
    """Calls the Anthropic Messages API using the anthropic SDK."""

    def __init__(
        self,
        api_key: str,
        model: str = "claude-haiku-4-5-20251001",
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ) -> None:
        try:
            import anthropic as _anthropic
        except ImportError as exc:
            raise ImportError(
                "anthropic package is required for --provider anthropic. "
                "Install it with: pip install 'cloudspill[ai]' or pip install anthropic"
            ) from exc

        self._client: Any = _anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.temperature = temperature
        self._max_tokens = max_tokens

    def complete(self, system: str, user: str) -> str:
        """Send a messages request to the Anthropic API."""
        message = self._client.messages.create(
            model=self.model,
            max_tokens=self._max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
            temperature=self.temperature,
        )
        return str(message.content[0].text)
