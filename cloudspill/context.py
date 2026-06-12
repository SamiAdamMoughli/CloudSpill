"""ScanContext — orchestrates the full scan pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from cloudspill.engine.rule_engine import RuleEngine
from cloudspill.engine.taint_engine import TaintEngine
from cloudspill.models.findings import Finding
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.taint import TaintResult
from cloudspill.parsers.registry import ParserRegistry
from cloudspill.rules import RuleRegistry


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


class ScanContext:
    """Owns the full scan lifecycle. Stateless workers, stateful context."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._parser_registry = ParserRegistry()
        self._rule_registry = RuleRegistry(enabled=config.rule_sets)

    def run(self, paths: list[Path]) -> ScanResult:
        """Execute the full pipeline: parse → graph → rules → taint."""
        nodes = self._parser_registry.parse_all(paths)
        graph = ResourceGraph.build(nodes)
        findings = RuleEngine(self._rule_registry).evaluate(nodes, graph)
        taint_results = TaintEngine(graph).propagate(findings)
        return ScanResult(
            findings=findings,
            taint_results=taint_results,
            graph=graph,
        )
