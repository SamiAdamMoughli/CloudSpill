"""TaintEngine — BFS propagation of findings through the resource graph."""

from __future__ import annotations

from cloudspill.models.findings import Finding
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.taint import TaintResult


class TaintEngine:
    """Propagates findings through the DAG via BFS, producing TaintResults."""

    def __init__(self, graph: ResourceGraph) -> None:
        self._graph = graph

    def propagate(self, findings: list[Finding]) -> list[TaintResult]:
        raise NotImplementedError
