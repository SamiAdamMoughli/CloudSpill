"""Parse-time error model — collected during parse_all(), surfaced in ScanMetadata."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ParseError:
    """A file that could not be parsed, with the reason."""

    file: str
    message: str
