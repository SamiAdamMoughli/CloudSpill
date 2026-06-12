"""Shape-normalizing helpers for python-hcl2 attribute values.

python-hcl2 is inconsistent about how it represents nested blocks and scalar
lists: a singleton block may arrive as a dict or a single-element list of
dicts, and a list attribute may arrive as a bare scalar. These helpers
normalize those shapes so rules can iterate without repeating defensive
``isinstance`` ladders.
"""

from __future__ import annotations

from typing import Any


def as_blocks(value: Any) -> list[dict[str, Any]]:
    """Normalize an hcl2 block value to a list of dicts.

    A dict becomes a one-element list; a list keeps only its dict members;
    anything else becomes an empty list.
    """
    if isinstance(value, list):
        return [b for b in value if isinstance(b, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def as_str_list(value: Any) -> list[str]:
    """Normalize a scalar-or-list attribute to a list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []
