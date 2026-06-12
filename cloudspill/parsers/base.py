"""Parser protocol — structural subtyping for all IaC parsers."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from cloudspill.models.nodes import IaCNode


class Parser(Protocol):
    """Interface every parser must satisfy.

    Implementations must provide:
        can_parse: determine if this parser handles the given file.
        parse: convert the file into a list of typed IaCNode objects.
    """

    def can_parse(self, path: Path) -> bool:
        """Return True if this parser can handle the given file path."""
        ...

    def parse(self, path: Path) -> list[IaCNode]:
        """Parse the file and return a list of IaCNode objects."""
        ...
