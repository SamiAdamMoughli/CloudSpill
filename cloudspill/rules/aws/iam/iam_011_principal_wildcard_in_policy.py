"""IAM-011: Identity policy contains a wildcard Principal.

Identity policies (attached to a user, group, or role) are not supposed to carry
a ``Principal`` at all — the principal *is* the entity the policy is attached to.
A ``Principal`` element that slips into one, especially a wildcard
(``"*"`` / ``{"AWS": "*"}``), is a sign the document was written as (or copied
from) a resource/trust policy and is granting access far more broadly than
intended.

This rule flags an identity policy (``aws_iam_policy`` or an inline
``aws_iam_*_policy``) whose Allow statement has a wildcard Principal. (Wildcard
trust on a role's assume_role_policy is handled by IAM-010.)
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.iam.policy_docs import (
    IDENTITY_POLICY_TYPES,
    identity_statements,
)
from cloudspill.rules.aws.utils.policy import is_wildcard_principal
from cloudspill.rules.base import register


@register
class IAMPrincipalWildcardInPolicy:
    """IAM-011: identity policy statement has a wildcard Principal."""

    rule_id = "IAM-011"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in IDENTITY_POLICY_TYPES:
            return []

        for stmt in identity_statements(node):
            if stmt.get("Effect") != "Allow":
                continue
            if "Principal" in stmt and is_wildcard_principal(stmt.get("Principal")):
                return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Identity policy contains a wildcard Principal",
            description=(
                'An identity policy statement specifies Principal "*". Identity '
                "policies should have no Principal; a wildcard one usually means a "
                "resource/trust policy was pasted here and is granting access far "
                "too broadly."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Remove the Principal element from the identity policy, or — if a "
                "resource policy was intended — move it to the resource and scope "
                "the Principal to specific ARNs."
            ),
            tags=frozenset(
                {
                    "iam",
                    "wildcard-principal",
                    "public-access",
                    "misconfiguration",
                    "aws",
                }
            ),
        )
