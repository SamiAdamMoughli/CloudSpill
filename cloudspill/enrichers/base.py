"""Enricher protocol — structural subtyping for all enrichment plugins."""

from __future__ import annotations

from typing import Protocol

from cloudspill.enrichers.types import EnrichedFinding
from cloudspill.models.findings import Finding
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.taint import TaintResult


class Enricher(Protocol):
    """Interface every enricher must satisfy.

    An enricher receives the full scan output and returns zero or more
    EnrichedFinding objects that augment the original findings with
    additional context (explanations, patches, confidence scores, etc.).

    Implementations must be stateless with respect to the scan — the same
    enricher instance may be called multiple times across scans.
    """

    def enrich(
        self,
        findings: list[Finding],
        taint_results: list[TaintResult],
        graph: ResourceGraph,
    ) -> list[EnrichedFinding]:
        """Enrich findings and return augmented results.

        Args:
            findings: all rule violations from the current scan.
            taint_results: taint propagation paths for each finding.
            graph: the full resource dependency graph.

        Returns:
            A list of EnrichedFinding objects. May be empty if enrichment
            is unavailable (e.g., model server unreachable).
        """
        ...
