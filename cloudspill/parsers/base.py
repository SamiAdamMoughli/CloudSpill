"""Parser protocol — structural subtyping for all IaC parsers."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from cloudspill.models.nodes import IaCNode


class Parser(Protocol):
    """Interface every parser must satisfy."""

    def can_parse(self, path: Path) -> bool: ...
    def parse(self, path: Path) -> list[IaCNode]: ...
