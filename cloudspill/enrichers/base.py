"""Enricher protocol — optional post-processing layer."""

from __future__ import annotations

from typing import Any, Protocol

from cloudspill.models.findings import Finding
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.taint import TaintResult


class Enricher(Protocol):
    """Optional enrichment stage between taint analysis and output."""

    def enrich(
        self,
        findings: list[Finding],
        taint_results: list[TaintResult],
        graph: ResourceGraph,
    ) -> list[dict[str, Any]]: ...
