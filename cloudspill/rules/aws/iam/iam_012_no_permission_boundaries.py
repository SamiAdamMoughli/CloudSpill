"""IAM-012: Role or user has no permissions boundary.

A permissions boundary is a managed policy that caps the *maximum* permissions an
IAM role or user can ever have, regardless of what its attached policies grant.
It is the key guardrail for safe permission delegation: without one, anyone who
can attach policies to the identity (or the identity itself, if it can do IAM)
can escalate to whatever they like. Boundaries are how you let teams self-serve
roles without handing out account-wide power.

This is a governance control (LOW). The rule flags an ``aws_iam_role`` or
``aws_iam_user`` with no ``permissions_boundary`` set.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_TARGET_TYPES = frozenset({"aws_iam_role", "aws_iam_user"})


@register
class IAMNoPermissionBoundary:
    """IAM-012: aws_iam_role / aws_iam_user has no permissions_boundary."""

    rule_id = "IAM-012"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _TARGET_TYPES:
            return []

        if str(node.attributes.get("permissions_boundary", "")).strip():
            return []

        kind = node.resource_type.replace("aws_iam_", "")
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title=f"IAM {kind} has no permissions boundary",
                description=(
                    f"This {node.resource_type} has no permissions_boundary, so "
                    "nothing caps the permissions it can be granted. There is no "
                    "guardrail against privilege escalation through later policy "
                    "attachments."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set permissions_boundary to a managed policy that defines the "
                    "maximum permissions this identity may ever have."
                ),
                tags=frozenset(
                    {
                        "iam",
                        "permissions-boundary",
                        "governance",
                        "least-privilege",
                        "aws",
                    }
                ),
            )
        ]
