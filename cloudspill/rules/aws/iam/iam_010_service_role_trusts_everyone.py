"""IAM-010: Role trust policy allows any principal to assume it.

A role whose ``assume_role_policy`` allows a wildcard principal (``"*"`` or
``{"AWS": "*"}``) can be assumed by anyone — any AWS account, and with no
condition, effectively the public. Combined with whatever permissions the role
holds, that is a direct path for an external party to obtain credentials inside
your account.

This rule flags an ``aws_iam_role`` whose trust policy has an Allow statement
with a wildcard principal.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.iam.policy_docs import trust_statements
from cloudspill.rules.aws.utils.policy import is_wildcard_principal
from cloudspill.rules.base import register


@register
class IAMRoleTrustsEveryone:
    """IAM-010: aws_iam_role assume_role_policy allows a wildcard principal."""

    rule_id = "IAM-010"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_iam_role":
            return []

        for stmt in trust_statements(node):
            if stmt.get("Effect") != "Allow":
                continue
            if is_wildcard_principal(stmt.get("Principal")):
                return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="IAM role can be assumed by any principal",
            description=(
                'The role\'s assume_role_policy allows Principal "*", so any AWS '
                "account — and with no condition, effectively anyone — can assume "
                "the role and obtain its permissions."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Restrict the trust policy Principal to specific account/role/"
                "service principals that legitimately need to assume the role."
            ),
            tags=frozenset(
                {
                    "iam",
                    "trust-policy",
                    "wildcard-principal",
                    "privilege-escalation",
                    "aws",
                }
            ),
        )
