"""ScanContext — orchestrates the full scan pipeline."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from cloudspill.engine.resolver import ConfigResolver
from cloudspill.engine.rule_engine import RuleEngine
from cloudspill.engine.taint_engine import TaintEngine
from cloudspill.enrichers.types import EnrichedFinding
from cloudspill.models.errors import ParseError
from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.taint import TaintResult
from cloudspill.parsers.registry import ParserRegistry
from cloudspill.rules import RuleRegistry

if TYPE_CHECKING:
    from cloudspill.enrichers.base import Enricher

logger = logging.getLogger(__name__)


@dataclass
class ScanMetadata:  # pylint: disable=too-few-public-methods
    """Diagnostic information about a completed scan."""

    files_scanned: int = 0
    parse_errors: list[ParseError] = field(default_factory=list)
    duration_seconds: float = 0.0


@dataclass(frozen=True)
class ScanConfig:
    """User-provided scan parameters."""

    rule_sets: set[str] | None = None
    min_severity: str = "LOW"
    show_taint: bool = False
    fail_on: str | None = None


@dataclass
class ScanResult:
    """Output of a complete scan."""

    findings: list[Finding] = field(default_factory=list)
    taint_results: list[TaintResult] = field(default_factory=list)
    graph: ResourceGraph = field(default_factory=ResourceGraph)
    enriched_findings: list[EnrichedFinding] = field(default_factory=list)
    metadata: ScanMetadata = field(default_factory=ScanMetadata)

    def filter(self, min_severity: str) -> ScanResult:
        """Return a new ScanResult containing only findings at or above min_severity."""
        order = list(Severity)
        min_idx = order.index(Severity(min_severity))

        def keep(f: Finding) -> bool:
            return order.index(f.severity) <= min_idx

        return ScanResult(
            findings=[f for f in self.findings if keep(f)],
            taint_results=[t for t in self.taint_results if keep(t.finding)],
            graph=self.graph,
            enriched_findings=[e for e in self.enriched_findings if keep(e.finding)],
            metadata=self.metadata,
        )


class ScanContext:
    """Owns the full scan lifecycle. Stateless workers, stateful context."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._parser_registry = ParserRegistry()
        self._rule_registry = RuleRegistry(enabled=config.rule_sets)
        self._enrichers: list[Enricher] = []

    def add_enricher(self, enricher: Enricher) -> None:
        """Register an enricher to run after taint analysis."""
        self._enrichers.append(enricher)

    def run(self, paths: list[Path]) -> ScanResult:
        """Execute the full pipeline: parse → graph → rules → taint → enrich."""
        start = time.monotonic()
        logger.info("Scanning %d file(s)", len(paths))

        nodes = self._parser_registry.parse_all(paths)
        parse_errors = list(self._parser_registry.errors)
        logger.debug(
            "Parsed %d node(s); %d parse error(s)", len(nodes), len(parse_errors)
        )

        nodes = ConfigResolver().resolve(nodes)
        logger.debug("Resolution produced %d node(s)", len(nodes))

        graph = ResourceGraph.build(nodes)
        findings = RuleEngine(self._rule_registry).evaluate(nodes, graph)
        taint_results = TaintEngine(graph).propagate(findings)
        logger.info(
            "Found %d finding(s), %d taint chain(s)",
            len(findings),
            len(taint_results),
        )

        enriched: list[EnrichedFinding] = []
        for enricher in self._enrichers:
            enriched.extend(enricher.enrich(findings, taint_results, graph))

        duration = time.monotonic() - start
        logger.info("Scan complete in %.2fs", duration)

        return ScanResult(
            findings=findings,
            taint_results=taint_results,
            graph=graph,
            enriched_findings=enriched,
            metadata=ScanMetadata(
                files_scanned=len(paths),
                parse_errors=parse_errors,
                duration_seconds=duration,
            ),
        )
