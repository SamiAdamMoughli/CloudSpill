"""IAM-005: Inline IAM policy used instead of a managed policy.

Inline policies (``aws_iam_role_policy``, ``aws_iam_user_policy``,
``aws_iam_group_policy``) live embedded on a single identity. They are harder to
audit and reuse, cannot be versioned or rolled back like managed policies, and
do not show up in a central policy inventory — so over-permissive grants hide in
them. AWS guidance is to prefer customer-managed policies.

This is a governance / hygiene control (LOW). The rule flags the presence of an
inline-policy resource.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.iam.policy_docs import INLINE_POLICY_TYPES
from cloudspill.rules.base import register


@register
class IAMInlinePolicy:
    """IAM-005: an inline-policy resource is used."""

    rule_id = "IAM-005"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in INLINE_POLICY_TYPES:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Inline IAM policy used instead of a managed policy",
                description=(
                    f"{node.resource_type} defines an inline policy. Inline "
                    "policies are harder to audit, version, and reuse, and they "
                    "stay out of the central policy inventory where over-broad "
                    "grants can hide."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Move the policy into a customer-managed aws_iam_policy and "
                    "attach it via an attachment resource."
                ),
                tags=frozenset(
                    {"iam", "inline-policy", "governance", "auditability", "aws"}
                ),
            )
        ]
