"""Helpers for parsing IAM / resource policy documents out of IaC attributes.

A ``policy`` attribute may be a pre-parsed dict or a JSON string, and the JSON
string is often wrapped in a Terraform heredoc (``<<EOF ... EOF``). These
helpers normalize all of those into a list of statement dicts and answer common
questions about a statement, so rules don't each re-implement the parsing.
"""

from __future__ import annotations

import json
from typing import Any


def as_statement_list(value: Any) -> list[dict[str, Any]]:
    """Coerce a policy ``Statement`` field to a list of statement dicts.

    A single statement may be written as one object rather than a list;
    non-dict members are discarded.
    """
    items = value if isinstance(value, list) else [value]
    return [stmt for stmt in items if isinstance(stmt, dict)]


def extract_statements(policy_raw: Any) -> list[dict[str, Any]]:
    """Extract policy statements from a raw ``policy`` attribute value.

    Handles a pre-parsed dict, a plain JSON string, and heredoc-wrapped JSON
    . Returns ``[]`` when the value cannot
    be parsed as a policy document.
    """
    if isinstance(policy_raw, dict):
        return as_statement_list(policy_raw.get("Statement", []))

    if isinstance(policy_raw, str):
        cleaned = policy_raw.strip()
        # Strip heredoc markers (<<EOF / <<-EOF ... EOF).
        if cleaned.startswith("<<"):
            first_newline = cleaned.index("\n") if "\n" in cleaned else len(cleaned)
            cleaned = cleaned[first_newline + 1 :]
            lines = cleaned.rsplit("\n", 1)
            if len(lines) == 2 and lines[1].strip().isalpha():
                cleaned = lines[0]
            cleaned = cleaned.strip()

        if cleaned.startswith("{"):
            try:
                doc = json.loads(cleaned)
                return as_statement_list(doc.get("Statement", []))
            except (json.JSONDecodeError, AttributeError):
                return []

    return []


def is_wildcard_principal(principal: Any) -> bool:
    """True if a statement ``Principal`` grants access to everyone.

    Matches the string ``"*"`` and the dict forms ``{"AWS": "*"}`` and
    ``{"AWS": ["*"]}`` (and the same for any other principal-type key).
    """
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for value in principal.values():
            values = value if isinstance(value, list) else [value]
            if "*" in values:
                return True
    return False
