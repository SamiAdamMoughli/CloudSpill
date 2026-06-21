"""EC2-007: Instance does not have termination protection enabled.

``disable_api_termination = true`` blocks the API/console from terminating an
instance until the flag is turned off, guarding against accidental or malicious
deletion of stateful or hard-to-rebuild hosts. It is off by default.

This is an availability / resilience control (LOW). The rule flags an
``aws_instance`` whose ``disable_api_termination`` is not true.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


def _is_true(value: object) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() == "true"


@register
class EC2TerminationProtectionDisabled:
    """EC2-007: aws_instance has disable_api_termination not enabled."""

    rule_id = "EC2-007"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_instance":
            return []

        if _is_true(node.attributes.get("disable_api_termination")):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Instance does not have termination protection enabled",
                description=(
                    "disable_api_termination is not true on this aws_instance, so "
                    "it can be terminated through the API or console with no "
                    "safeguard, risking accidental or malicious deletion."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set disable_api_termination = true on instances whose loss "
                    "would be disruptive or hard to recover from."
                ),
                tags=frozenset({"ec2", "termination-protection", "resilience", "aws"}),
            )
        ]
