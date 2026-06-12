"""GeminiProvider — native Google Generative Language API.

Uses generateContent directly with the x-goog-api-key header.
temperature is intentionally omitted — Gemini 3.x reasoning is
optimised for its defaults and setting it is no longer recommended.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from cloudspill.enrichers.providers.base import ProviderError

logger = logging.getLogger(__name__)

_BASE = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiProvider:
    """Calls the Gemini generateContent endpoint via the native REST API."""

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-3.5-flash",
        timeout: int = 60,
        thinking_level: str = "low",
    ) -> None:
        self._headers = {
            "x-goog-api-key": api_key,
            "Content-Type": "application/json",
        }
        self.model = model
        self._timeout = timeout
        self._thinking_level = thinking_level
        self._url = f"{_BASE}/{model}:generateContent"

    def complete(self, system: str, user: str) -> str:
        payload: dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {
                "thinkingConfig": {"thinkingLevel": self._thinking_level},
            },
        }
        logger.debug("Gemini request -> %s", self._url)
        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(self._url, json=payload, headers=self._headers)
                response.raise_for_status()
                body: dict[str, Any] = response.json()
        except httpx.HTTPStatusError as exc:
            detail = exc.response.text[:200].replace("\n", " ")
            raise ProviderError(
                f"Gemini API returned HTTP {exc.response.status_code}: {detail}"
            ) from exc
        except httpx.RequestError as exc:
            raise ProviderError(f"Gemini API request failed: {exc}") from exc

        try:
            return str(body["candidates"][0]["content"]["parts"][0]["text"]).strip()
        except (KeyError, IndexError, TypeError) as exc:
            block = body.get("promptFeedback", {}).get("blockReason")
            reason = f" (blocked: {block})" if block else ""
            raise ProviderError(f"Gemini API returned no usable text{reason}") from exc
