"""VPC-009: Security group has a placeholder or empty description.

A security group (or rule) whose description is blank or a throwaway placeholder
("temp", "test", "todo", "changeme", "xxx", "asdf") is almost always a rule that
was added in a hurry and never revisited — the kind of "temporary" open port that
quietly becomes permanent. A meaningful description is also what makes a rule
auditable later: why it exists and who owns it.

This is a hygiene / auditability control (LOW). The rule flags an
``aws_security_group``, ``aws_security_group_rule``, or
``aws_vpc_security_group_ingress_rule`` whose description is empty or a known
placeholder.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_TARGET_TYPES = frozenset(
    {
        "aws_security_group",
        "aws_security_group_rule",
        "aws_vpc_security_group_ingress_rule",
        "aws_vpc_security_group_egress_rule",
    }
)
_PLACEHOLDERS = frozenset(
    {"", "temp", "tmp", "temporary", "test", "todo", "tbd", "changeme", "xxx", "asdf", "foo"}
)


@register
class VPCSecurityGroupTempDescription:
    """VPC-009: security group/rule has a placeholder or empty description."""

    rule_id = "VPC-009"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _TARGET_TYPES:
            return []

        description = str(node.attributes.get("description", "")).strip().lower()
        if description not in _PLACEHOLDERS:
            return []

        shown = description or "empty"
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Security group has a placeholder description",
                description=(
                    f"The description on this {node.resource_type} is {shown}. "
                    "Placeholder/blank descriptions usually mark a rushed, "
                    "never-revisited rule and leave the rule's intent and owner "
                    "undocumented for later audit."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Give the security group/rule a meaningful description stating "
                    "what it allows and why."
                ),
                tags=frozenset(
                    {"vpc", "security-group", "auditability", "hygiene", "aws"}
                ),
            )
        ]
