"""LAMBDA-010: Function execution role grants wildcard admin permissions.

A Lambda's execution role is assumed automatically on every invocation, so its
permissions are exactly what the function's code (and anything that can inject
into it via a dependency or input) can do. If that role allows a wildcard action
on a wildcard resource, a single code-execution bug in the function escalates to
full account administrator.

This rule walks ``aws_lambda_function`` → ``aws_iam_role`` through the graph,
then inspects the role's policies (inline ``aws_iam_role_policy``, the role's own
``inline_policy`` blocks, and attached ``aws_iam_policy`` documents) for an
``Allow`` with wildcard action and resource.
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
    for stmt in extract_statements(policy_raw):
        if stmt.get("Effect") != "Allow":
            continue
        if _has_wildcard(stmt.get("Action")) and _has_wildcard(stmt.get("Resource")):
            return True
    return False


@register
class LambdaOverpermissiveExecutionRole:
    """LAMBDA-010: execution role grants wildcard admin permissions."""

    rule_id = "LAMBDA-010"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_lambda_function":
            return []

        role = self._role(node, graph)
        if role is None or not self._role_is_admin(role, graph):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Lambda execution role grants wildcard admin permissions",
                description=(
                    f"This function's execution role '{role.name}' has a policy "
                    "allowing a wildcard action on a wildcard resource. A "
                    "code-execution bug in the function escalates directly to full "
                    "account administrator."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Scope the execution role to the specific actions and resources "
                    "the function needs; never grant Action \"*\" / Resource \"*\"."
                ),
                tags=frozenset(
                    {"lambda", "iam", "privilege-escalation", "execution-role", "aws"}
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
        for block in as_blocks(role.attributes.get("inline_policy")):
            if _is_admin_doc(block.get("policy")):
                return True

        for edge in graph.incoming(role.node_id):
            source = graph.get_node(edge.source)
            if source is None:
                continue
            if source.resource_type == "aws_iam_role_policy" and _is_admin_doc(
                source.attributes.get("policy")
            ):
                return True
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
