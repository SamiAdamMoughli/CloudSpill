"""IAM-007: Policy trusts or grants the account root principal.

Using ``arn:aws:iam::<account-id>:root`` as a principal delegates to the *whole*
account: every current and future IAM identity in it is implicitly trusted, and
the grant survives even after the specific role/user that needed it is deleted.
For trust policies and resource policies this is far broader than naming the
exact roles that need access, and it quietly couples your security to the entire
other account.

This rule flags an ``aws_iam_role`` trust policy (or an identity policy that
carries a Principal) whose principal is an account-root ARN.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.iam.policy_docs import (
    IDENTITY_POLICY_TYPES,
    aws_principals,
    identity_statements,
    trust_statements,
)
from cloudspill.rules.base import register


def _statements(node: IaCNode) -> list[dict]:
    if node.resource_type == "aws_iam_role":
        return trust_statements(node)
    if node.resource_type in IDENTITY_POLICY_TYPES:
        return identity_statements(node)
    return []


@register
class IAMRootAccountInUse:
    """IAM-007: a policy uses the account-root principal."""

    rule_id = "IAM-007"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        for stmt in _statements(node):
            if stmt.get("Effect") != "Allow":
                continue
            if any(p.rstrip("/").endswith(":root") for p in aws_principals(stmt)):
                return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Policy trusts or grants the account root principal",
            description=(
                "A statement names an account-root principal (:root), delegating "
                "to every identity in that account rather than the specific roles "
                "that need access. The grant is broad and outlives the entity that "
                "needed it."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Replace the :root principal with the exact role/user ARNs that "
                "require access."
            ),
            tags=frozenset({"iam", "root-principal", "over-broad-trust", "aws"}),
        )
