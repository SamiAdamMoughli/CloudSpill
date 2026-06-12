"""Formatter protocol — the contract every output format implements.

The table, JSON, and Markdown formatters all satisfy this shape. The Mermaid
graph formatter is intentionally *not* a Formatter: it renders the resource
graph (not a findings list) and has its own signature.
"""

from __future__ import annotations

from typing import Protocol

from cloudspill.models.findings import Finding
from cloudspill.models.taint import TaintResult


class Formatter(Protocol):  # pylint: disable=too-few-public-methods
    """Interface for scan-result output formatters.

    Implementations take the findings and taint results and return a rendered
    string. Side effects (e.g. printing a Rich table) are allowed, but the
    return value is the canonical text form.
    """

    def format(
        self, findings: list[Finding], taint_results: list[TaintResult]
    ) -> str: ...
