"""IAM-003: AdministratorAccess (or PowerUserAccess) is attached.

Attaching the AWS-managed ``AdministratorAccess`` policy grants full control of
the account; ``PowerUserAccess`` grants everything except IAM. Either on a role,
user, or group is a major standing-privilege risk — and on a service/instance
role it turns any workload compromise into account takeover.

This rule flags an IAM policy attachment whose ``policy_arn`` is one of these
account-wide managed policies.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.iam.policy_docs import ATTACHMENT_TYPES
from cloudspill.rules.base import register

_ADMIN_POLICY_ARNS = frozenset(
    {
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
    }
)


@register
class IAMAdministratorAccess:
    """IAM-003: attachment references AdministratorAccess/PowerUserAccess."""

    rule_id = "IAM-003"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in ATTACHMENT_TYPES:
            return []

        policy_arn = str(node.attributes.get("policy_arn", "")).strip()
        if policy_arn not in _ADMIN_POLICY_ARNS:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="AdministratorAccess / PowerUserAccess is attached",
                description=(
                    f"This attachment grants {policy_arn}, an account-wide managed "
                    "policy. The principal holds standing administrative (or "
                    "near-administrative) privilege over the account."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Replace the managed admin policy with a least-privilege "
                    "policy scoped to the actions and resources the principal "
                    "actually needs."
                ),
                tags=frozenset(
                    {"iam", "administrator-access", "over-privilege", "aws"}
                ),
            )
        ]
