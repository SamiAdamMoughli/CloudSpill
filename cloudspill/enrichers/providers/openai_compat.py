"""OpenAICompatProvider — any OpenAI-compatible server (Ollama, vLLM, Gemini).

No external SDK required — uses httpx against /v1/chat/completions directly.
Default provider when --ai is used without --provider.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from cloudspill.enrichers.providers.base import ProviderError

logger = logging.getLogger(__name__)

# Status codes that are transient and worth retrying.
_RETRYABLE = {429, 500, 502, 503, 504}
_MAX_RETRIES = 3
_BASE_BACKOFF = 5.0  # seconds; doubles each retry


class OpenAICompatProvider:
    """Calls any server that speaks the OpenAI chat-completions wire format."""

    def __init__(
        self,
        base_url: str = "http://localhost:11434/v1",
        model: str = "qwen3.6-35b-a3b",
        temperature: float = 0.1,
        timeout: int = 120,
        api_key: str | None = None,
    ) -> None:
        self.model = model
        self.temperature = temperature
        self._timeout = timeout
        self._headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        # Normalise: always end with /chat/completions
        self._url = base_url.rstrip("/") + "/chat/completions"

    @property
    def base_url(self) -> str:
        return self._url

    def complete(self, system: str, user: str) -> str:
        """POST to /chat/completions and return the raw message content.

        Retries up to _MAX_RETRIES times on transient errors (429, 503, …)
        with exponential backoff. Re-raises on the final attempt.
        """
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self.temperature,
        }
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                with httpx.Client(timeout=self._timeout) as client:
                    response = client.post(
                        self._url, json=payload, headers=self._headers
                    )
                    if response.status_code in _RETRYABLE and attempt < _MAX_RETRIES:
                        # Honour Retry-After if present, else exponential backoff.
                        retry_after = response.headers.get("Retry-After")
                        wait = (
                            float(retry_after)
                            if retry_after
                            else _BASE_BACKOFF * (2**attempt)
                        )
                        logger.warning(
                            "Provider returned %s; retrying in %.0fs (%d/%d)",
                            response.status_code,
                            wait,
                            attempt + 1,
                            _MAX_RETRIES,
                        )
                        time.sleep(wait)
                        continue
                    response.raise_for_status()
                    body: dict[str, Any] = response.json()
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code in _RETRYABLE and attempt < _MAX_RETRIES:
                    wait = _BASE_BACKOFF * (2**attempt)
                    logger.warning(
                        "HTTP %s from provider; retrying in %.0fs (%d/%d)",
                        exc.response.status_code,
                        wait,
                        attempt + 1,
                        _MAX_RETRIES,
                    )
                    time.sleep(wait)
                    last_exc = exc
                    continue
                raise ProviderError(
                    f"Provider returned HTTP {exc.response.status_code} "
                    f"from {self._url}"
                ) from exc
            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                if attempt < _MAX_RETRIES:
                    logger.warning(
                        "Connection error (%s); retrying in %.0fs (%d/%d)",
                        type(exc).__name__,
                        _BASE_BACKOFF * (2**attempt),
                        attempt + 1,
                        _MAX_RETRIES,
                    )
                    time.sleep(_BASE_BACKOFF * (2**attempt))
                    last_exc = exc
                    continue
                raise ProviderError(
                    f"Could not reach inference server at {self._url}: {exc}"
                ) from exc

            try:
                return str(body["choices"][0]["message"]["content"]).strip()
            except (KeyError, IndexError, TypeError) as exc:
                raise ProviderError(
                    f"Malformed chat-completion response from {self._url}"
                ) from exc

        raise ProviderError(  # pragma: no cover - loop always returns/raises
            f"Exhausted retries contacting {self._url}: {last_exc}"
        )
