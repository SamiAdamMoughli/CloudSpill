"""LLMProvider — structural protocol for all LLM backends."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class LLMProvider(Protocol):
    """Minimal interface every LLM backend must satisfy.

    A provider is responsible only for turning a (system, user) prompt pair
    into a raw text response. JSON parsing, thinking-tag stripping, and
    graceful fallback all live in AIEnricher — not here.

    Implementations should raise on any failure (network error, auth error,
    rate limit, etc.) so the caller can handle graceful degradation uniformly.
    """

    def complete(self, system: str, user: str) -> str:
        """Send a chat completion request and return the raw text content."""
        ...
