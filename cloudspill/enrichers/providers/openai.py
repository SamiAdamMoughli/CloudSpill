"""OpenAIProvider — OpenAI API via the official openai SDK.

Install the optional dependency before use:
    pip install "cloudspill[ai]"   # installs openai + anthropic
    pip install openai>=1.0        # or just openai
"""

from __future__ import annotations

from typing import Any


class OpenAIProvider:
    """Calls OpenAI's chat completions endpoint using the openai SDK."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        temperature: float = 0.1,
    ) -> None:
        try:
            import openai as _openai
        except ImportError as exc:
            raise ImportError(
                "openai package is required for --provider openai. "
                "Install it with: pip install 'cloudspill[ai]' or pip install openai"
            ) from exc

        self._client: Any = _openai.OpenAI(api_key=api_key)
        self.model = model
        self.temperature = temperature

    def complete(self, system: str, user: str) -> str:
        """Send a chat completion request to the OpenAI API."""
        response = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=self.temperature,
        )
        return response.choices[0].message.content or ""
