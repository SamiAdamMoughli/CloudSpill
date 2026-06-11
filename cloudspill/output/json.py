"""JSON output formatter."""

from __future__ import annotations

from cloudspill.models.findings import Finding
from cloudspill.models.taint import TaintResult


class JsonFormatter:
    def format(self, findings: list[Finding], taint_results: list[TaintResult]) -> str:
        raise NotImplementedError
