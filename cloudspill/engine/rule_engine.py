"""RuleEngine — walks nodes × rules, collects findings."""

from __future__ import annotations

from cloudspill.models.findings import Finding
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules import RuleRegistry


class RuleEngine:
    """Visitor-pattern evaluator: every node is checked against every enabled rule."""

    def __init__(self, registry: RuleRegistry) -> None:
        self._registry = registry

    def evaluate(self, nodes: list[IaCNode], graph: ResourceGraph) -> list[Finding]:
        raise NotImplementedError
