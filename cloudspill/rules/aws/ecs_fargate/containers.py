"""Shared parsing for ECS task definitions' ``container_definitions``.

In Terraform, ``aws_ecs_task_definition.container_definitions`` is a JSON string
— almost always produced by ``jsonencode([...])`` or written as a heredoc. The
ConfigResolver does not evaluate ``jsonencode`` (it is a function call), so the
value can reach a rule either as an already-parsed Python list (rare) or as a
JSON / heredoc string. These helpers normalize all of those into a list of
container dicts so the ECS rules don't each re-implement the parsing.

This module deliberately registers no rules; it is a helper imported by the
``ecs_*`` rule modules (mirroring how ``utils/policy.py`` backs the IAM rules).
"""

from __future__ import annotations

import json
from typing import Any


def parse_container_definitions(value: Any) -> list[dict[str, Any]]:
    """Return the list of container dicts from a container_definitions value.

    Accepts a pre-parsed list, a JSON string, or a heredoc-wrapped JSON string.
    Returns ``[]`` when the value cannot be parsed as a list of objects.
    """
    if isinstance(value, list):
        return [c for c in value if isinstance(c, dict)]

    if not isinstance(value, str):
        return []

    cleaned = _strip_heredoc(value.strip())

    # jsonencode(...) sometimes survives resolution as a literal string; there
    # is nothing parseable inside it, so bail rather than guess.
    if not cleaned.startswith("["):
        return []

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        return []

    return [c for c in parsed if isinstance(c, dict)] if isinstance(parsed, list) else []


def _strip_heredoc(text: str) -> str:
    """Strip a ``<<EOF`` / ``<<-EOF`` ... ``EOF`` wrapper, if present."""
    if not text.startswith("<<"):
        return text
    first_newline = text.index("\n") if "\n" in text else len(text)
    body = text[first_newline + 1 :]
    head, _, tail = body.rpartition("\n")
    if tail.strip().isalpha():  # closing heredoc marker line
        body = head
    return body.strip()
