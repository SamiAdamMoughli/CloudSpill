"""RuleEngine — walks nodes × rules, collects findings.

Uses the Visitor pattern: every node is checked against every enabled rule.
Children are visited recursively so nested blocks are not missed.
"""

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
        """Run all registered rules against all nodes. Returns deduplicated findings."""
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        for node in nodes:
            self._visit(node, graph, findings, seen)

        return findings

    def _visit(
        self,
        node: IaCNode,
        graph: ResourceGraph,
        findings: list[Finding],
        seen: set[tuple[str, str]],
    ) -> None:
        """Check one node against all rules, then recurse into children."""
        for rule in self._registry.rules:
            for finding in rule.check(node, graph):
                key = (finding.rule_id, finding.resource)
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)

        for child in node.children:
            self._visit(child, graph, findings, seen)
