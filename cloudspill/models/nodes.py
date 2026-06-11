"""IaCNode — typed, tree-structured AST nodes for infrastructure code."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class IaCNode:
    """A single infrastructure-as-code construct (resource, data, variable, etc.)."""

    node_id: str
    node_type: str
    resource_type: str
    name: str
    attributes: dict[str, Any]
    children: tuple[IaCNode, ...]
    source_file: str
    line: int
