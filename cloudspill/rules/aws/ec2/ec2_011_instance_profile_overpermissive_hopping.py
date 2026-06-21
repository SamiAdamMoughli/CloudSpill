"""EC2-011: Instance profile grants an admin-level role (credential hopping).

An instance profile hands its role's temporary credentials to anything running
on the instance, reachable through the metadata endpoint. If that role grants
wildcard permissions (``Action: "*"`` on ``Resource: "*"``), then any code
execution on the instance — including via an app vulnerability — escalates
straight to account administrator. This is the classic "credential hopping"
path from a single compromised host to the whole account.

This rule walks ``aws_iam_instance_profile`` → ``aws_iam_role`` through the
graph, then inspects the role's policies (inline ``aws_iam_role_policy``, the
role's own ``inline_policy`` blocks, and attached ``aws_iam_policy`` documents)
for an ``Allow`` statement with a wildcard action and resource.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.aws.utils.policy import extract_statements
from cloudspill.rules.base import register


def _has_wildcard(value: Any) -> bool:
    items = value if isinstance(value, list) else [value]
    return any(str(item).strip() == "*" for item in items)


def _is_admin_doc(policy_raw: Any) -> bool:
    """True if a policy doc has an Allow with wildcard Action and Resource."""
    for stmt in extract_statements(policy_raw):
        if stmt.get("Effect") != "Allow":
            continue
        if _has_wildcard(stmt.get("Action")) and _has_wildcard(stmt.get("Resource")):
            return True
    return False


@register
class EC2InstanceProfileOverpermissive:
    """EC2-011: instance profile's role grants wildcard admin permissions."""

    rule_id = "EC2-011"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_iam_instance_profile":
            return []

        role = self._role(node, graph)
        if role is None or not self._role_is_admin(role, graph):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Instance profile grants an admin-level role",
                description=(
                    f"This instance profile's role '{role.name}' has a policy that "
                    "allows a wildcard action on a wildcard resource. Any code "
                    "execution on an attached instance can read these credentials "
                    "and escalate to full account administrator."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Scope the role's policies to the specific actions and "
                    "resources the workload needs; never attach AdministratorAccess "
                    "or Action \"*\"/Resource \"*\" to an instance profile role."
                ),
                tags=frozenset(
                    {"ec2", "iam", "privilege-escalation", "instance-profile", "aws"}
                ),
            )
        ]

    @staticmethod
    def _role(node: IaCNode, graph: ResourceGraph) -> IaCNode | None:
        for edge in graph.outgoing(node.node_id):
            target = graph.get_node(edge.target)
            if target is not None and target.resource_type == "aws_iam_role":
                return target
        return None

    @classmethod
    def _role_is_admin(cls, role: IaCNode, graph: ResourceGraph) -> bool:
        # Inline policy blocks declared directly on the role.
        for block in as_blocks(role.attributes.get("inline_policy")):
            if _is_admin_doc(block.get("policy")):
                return True

        for edge in graph.incoming(role.node_id):
            source = graph.get_node(edge.source)
            if source is None:
                continue
            # Inline policy resource attached to the role.
            if source.resource_type == "aws_iam_role_policy" and _is_admin_doc(
                source.attributes.get("policy")
            ):
                return True
            # Managed-policy attachment → follow to the aws_iam_policy document.
            if source.resource_type == "aws_iam_role_policy_attachment":
                for pol_edge in graph.outgoing(source.node_id):
                    pol = graph.get_node(pol_edge.target)
                    if (
                        pol is not None
                        and pol.resource_type == "aws_iam_policy"
                        and _is_admin_doc(pol.attributes.get("policy"))
                    ):
                        return True
        return False
