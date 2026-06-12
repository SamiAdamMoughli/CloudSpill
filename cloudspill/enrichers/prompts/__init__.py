"""PromptLoader — reads provider-specific prompt templates and interpolates fields.

Template resolution order:
    prompts/{provider}/{mode}.txt   — provider-specific (e.g. gemini/explain.txt)
    prompts/default/{mode}.txt      — generic fallback

Each template is plain text with {identifier} placeholders. Multi-line JSON
blocks in templates are left untouched — only bare {word} patterns are replaced.

Usage:
    system = PromptLoader.render("explain", provider="gemini", rule_id="AZ-NSG-001", ...)

The cache is module-level: templates are read from disk once per process.
Call PromptLoader.clear_cache() in tests to force a re-read.
"""

from __future__ import annotations

import re
from pathlib import Path

# Matches only {identifier} — leaves {"key": "value"} JSON blocks untouched.
_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")

_PROMPTS_DIR = Path(__file__).parent

VALID_MODES = frozenset({"explain", "fix", "triage"})

_FALLBACK = (
    "You are a cloud security expert. You will be given a security finding "
    "from a static analysis tool. Respond with a JSON object containing:\n"
    '  "explanation": a 2-3 sentence plain-English explanation of the risk\n'
    '  "fix": a short Terraform or Dockerfile snippet that fixes it\n'
    '  "confidence": a float 0.0-1.0 representing your certainty\n'
    "Return only the JSON object, no prose, no markdown code fences."
)

# Cache key: "{provider}:{mode}"
_cache: dict[str, str] = {}


class PromptLoader:
    """Loads and renders prompt templates from the prompts/ directory."""

    @classmethod
    def load(cls, mode: str, provider: str = "default") -> str:
        """Return the raw template for *mode*, resolved for *provider*.

        Resolution order:
          1. prompts/{provider}/{mode}.txt
          2. prompts/default/{mode}.txt
          3. built-in _FALLBACK string

        Raises ValueError for unrecognised mode names.
        """
        if mode not in VALID_MODES:
            raise ValueError(
                f"Unknown prompt mode '{mode}'. "
                f"Choose from: {', '.join(sorted(VALID_MODES))}"
            )

        cache_key = f"{provider}:{mode}"
        if cache_key in _cache:
            return _cache[cache_key]

        candidates = [
            _PROMPTS_DIR / provider / f"{mode}.txt",
            _PROMPTS_DIR / "default" / f"{mode}.txt",
        ]
        for path in candidates:
            if path.exists():
                try:
                    _cache[cache_key] = path.read_text(encoding="utf-8")
                    return _cache[cache_key]
                except OSError:
                    continue

        _cache[cache_key] = _FALLBACK
        return _cache[cache_key]

    @classmethod
    def render(cls, mode: str, provider: str = "default", **fields: str) -> str:
        """Load the template for *mode*/*provider* and interpolate *fields*.

        Unknown placeholders in the template are left as-is. Unknown keys in
        *fields* are silently ignored.
        """
        template = cls.load(mode, provider=provider)
        return _PLACEHOLDER_RE.sub(
            lambda m: fields.get(m.group(1), m.group(0)), template
        )

    @classmethod
    def clear_cache(cls) -> None:
        """Evict all cached templates. Use in tests to force a re-read."""
        _cache.clear()

    @classmethod
    def is_cached(cls, mode: str, provider: str = "default") -> bool:
        """Return True if *mode*/*provider* is currently in the cache."""
        return f"{provider}:{mode}" in _cache
