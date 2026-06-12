"""Rule protocol and class-level registration system."""

from __future__ import annotations

from typing import Any, Protocol

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode

# Module-level registry populated by @register at import time.
# Python's module cache ensures each class is registered exactly once
# per process regardless of how many times the module is imported.
_RULE_CLASSES: list[type[Any]] = []


def register(cls: type[Any]) -> type[Any]:
    """Class decorator: register a rule for auto-discovery by RuleRegistry.

    Usage::

        @register
        class MyNewRule:
            rule_id = "MYNS-001"
            severity = Severity.HIGH

            def check(self, node, graph): ...

    Adding the decorator is the only step needed — no changes to __init__.py.
    """
    if cls not in _RULE_CLASSES:
        _RULE_CLASSES.append(cls)
    return cls


def get_registered_rules() -> list[Any]:
    """Return one fresh instance of every registered rule class."""
    return [cls() for cls in _RULE_CLASSES]


class Rule(Protocol):  # pylint: disable=too-few-public-methods
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
        ...  # pylint: disable=unnecessary-ellipsis
