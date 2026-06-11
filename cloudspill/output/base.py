"""Formatter protocol — one implementation per output format."""

from __future__ import annotations

from typing import Protocol

from cloudspill.models.findings import Finding
from cloudspill.models.taint import TaintResult


class Formatter(Protocol):
    """Interface for scan result output formatters."""

    def format(self, findings: list[Finding], taint_results: list[TaintResult]) -> str: ...
