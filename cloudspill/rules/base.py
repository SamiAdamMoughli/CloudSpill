"""Rule protocol and RuleRegistry."""

from __future__ import annotations

from typing import Protocol

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode


class Rule(Protocol):
    """Interface every security rule must satisfy."""

    rule_id: str
    severity: Severity

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]: ...