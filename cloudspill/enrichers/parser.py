"""parse_llm_response — robust normalisation of raw LLM output.

LLMs are inconsistent: they wrap JSON in code fences, prefix it with prose,
truncate mid-object when context limits are hit, or ignore the JSON instruction
entirely and return a plain-English explanation. This module handles all of
those cases so AIEnricher never has to reason about raw strings.

Public API:
    parse_llm_response(content)  → dict[str, Any] | None
    strip_think_tags(content)    → str

Internal pipeline (each step short-circuits on success):
    1. strip_think_tags          — remove <think>…</think> blocks
    2. direct json.loads         — most well-behaved models succeed here
    3. _strip_code_fences        — ```json … ``` or ``` … ```
    4. _extract_json_object      — balanced {…} found inside prose
    5. _repair_partial_json      — model was cut off mid-stream
    6. prose fallback            — wrap plain text in explanation field
"""

from __future__ import annotations

import json
import re
from typing import Any

# <think>…</think> with optional tag attributes; DOTALL so newlines are matched.
_THINK_RE = re.compile(r"<think[^>]*>.*?</think>", re.DOTALL | re.IGNORECASE)

# ```json\n…\n```  or  ```\n…\n```  — the language label is optional.
_CODE_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


# ── Public helpers ────────────────────────────────────────────────────────────


def strip_think_tags(content: str) -> str:
    """Remove every <think>…</think> block from *content* and strip whitespace."""
    return _THINK_RE.sub("", content).strip()


# ── Internal normalisation steps ──────────────────────────────────────────────


def _strip_code_fences(text: str) -> str:
    """Return the content inside the first markdown code fence, or *text* unchanged."""
    m = _CODE_FENCE_RE.search(text)
    return m.group(1).strip() if m else text


def _extract_json_object(text: str) -> str | None:
    """Find the first balanced {…} block in *text* using a proper state machine.

    Handles nested objects and escaped characters inside strings.
    Returns the extracted substring or None if no balanced block exists.
    """
    start = text.find("{")
    if start == -1:
        return None

    in_string = False
    escape_next = False
    depth = 0

    for i, ch in enumerate(text[start:], start):
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]

    return None  # unmatched opening brace


def _repair_partial_json(text: str) -> str | None:
    """Close a truncated JSON object by appending the missing delimiters.

    Walks the fragment with a state machine tracking brace/bracket depth and
    string state, then appends the characters needed to close all open
    structures. Returns a candidate string only when json.loads accepts it.
    """
    start = text.find("{")
    if start == -1:
        return None
    fragment = text[start:]

    in_string = False
    escape_next = False
    brace_depth = 0
    bracket_depth = 0

    for ch in fragment:
        if escape_next:
            escape_next = False
            continue
        if ch == "\\" and in_string:
            escape_next = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            brace_depth += 1
        elif ch == "}":
            brace_depth -= 1
        elif ch == "[":
            bracket_depth += 1
        elif ch == "]":
            bracket_depth -= 1

    # Already balanced — nothing to repair (let the caller decide what to do).
    if brace_depth <= 0 and not in_string:
        return None

    suffix = ""
    if in_string:
        suffix += '"'
    suffix += "]" * max(0, bracket_depth)
    suffix += "}" * max(0, brace_depth)

    candidate = fragment + suffix
    try:
        result = json.loads(candidate)
        return candidate if isinstance(result, dict) else None
    except json.JSONDecodeError:
        return None


# ── Main entry point ──────────────────────────────────────────────────────────


def parse_llm_response(content: str) -> dict[str, Any] | None:
    """Parse a raw LLM response string into a structured dict.

    Returns None *only* when *content* is empty or whitespace-only.
    For all non-empty input — including pure prose — returns a dict
    with at least the keys the caller expects ("explanation", "fix",
    "confidence"), either parsed from JSON or synthesised from prose.

    Pipeline
    --------
    1. strip_think_tags — remove <think>…</think>
    2. Direct json.loads — succeeds for well-behaved models
    3. Strip markdown code fences (```json … ```) and retry
    4. _extract_json_object — pull {…} from surrounding prose
    5. _repair_partial_json — close truncated/cut-off objects
    6. Prose fallback — {"explanation": <text>, "fix": "", "confidence": 0.3}
    """
    if not content or not content.strip():
        return None

    # Step 1 — strip think tags
    text = strip_think_tags(content)
    if not text:
        return None

    # Step 2 — direct parse (most compliant models land here)
    try:
        result = json.loads(text)
        if isinstance(result, dict):
            return result
    except json.JSONDecodeError:
        pass

    # Step 3 — strip markdown code fences and retry
    defenced = _strip_code_fences(text)
    if defenced != text:
        try:
            result = json.loads(defenced)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            text = defenced  # continue from inside the fence

    # Step 4 — extract the first balanced {…} block from surrounding prose
    extracted = _extract_json_object(text)
    if extracted:
        try:
            result = json.loads(extracted)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

    # Step 5 — repair a truncated object (missing closing braces / open string)
    repaired = _repair_partial_json(text)
    if repaired:
        try:
            result = json.loads(repaired)
            if isinstance(result, dict):
                return result
        except json.JSONDecodeError:
            pass

    # Step 6 — prose fallback: preserve whatever the model said as explanation
    return {"explanation": text, "fix": "", "confidence": 0.3}
