"""Rule protocol — structural subtyping for all security rules."""

from __future__ import annotations

from typing import Protocol

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode


class Rule(Protocol):
    """Interface every security rule must satisfy.

    Implementations must provide:
        rule_id: unique identifier (e.g. 'S3-001', 'IAM-003').
        severity: the severity level of findings this rule emits.
        check: inspect a node and return any findings.
    """

    rule_id: str
    severity: Severity

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        """Inspect a single IaCNode and return any findings.

        Args:
            node: the infrastructure resource to check.
            graph: the full resource graph, for cross-resource reasoning.

        Returns:
            A list of Finding objects. Empty if the node passes the check.
        """
        ...
