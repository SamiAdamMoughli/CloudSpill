"""IAM-006: Cross-account role trust without an external ID (confused deputy).

When a role's ``assume_role_policy`` trusts a principal in *another* account
(an ARN or that account's ``:root``), the trusted third party should be required
to pass an agreed ``sts:ExternalId``. Without it, the role is vulnerable to the
classic confused-deputy attack: a different customer of that third party can
trick it into assuming your role on their behalf. (MFA conditions are the other
acceptable guard.)

This rule flags an ``aws_iam_role`` whose trust statement allows a cross-account
AWS principal for ``sts:AssumeRole`` with neither an ``sts:ExternalId`` nor an
MFA condition. Wildcard-principal trust is reported by IAM-010 instead.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.iam.policy_docs import (
    aws_principals,
    condition_keys,
    statement_enforces_mfa,
    trust_statements,
)
from cloudspill.rules.base import register


def _is_cross_account_arn(principal: str) -> bool:
    """An IAM ARN / account-root principal (not a wildcard or service)."""
    return principal.startswith("arn:aws:iam::") and principal != "*"


@register
class IAMCrossAccountTrustNoExternalId:
    """IAM-006: cross-account trust missing sts:ExternalId / MFA."""

    rule_id = "IAM-006"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_iam_role":
            return []

        for stmt in trust_statements(node):
            if stmt.get("Effect") != "Allow":
                continue
            principals = aws_principals(stmt)
            if not any(_is_cross_account_arn(p) for p in principals):
                continue
            keys = condition_keys(stmt)
            if "sts:externalid" in keys or statement_enforces_mfa(stmt):
                continue
            return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Cross-account role trust has no external ID",
            description=(
                "The role's trust policy allows a principal in another account to "
                "assume it without an sts:ExternalId (or MFA) condition. This "
                "exposes the role to confused-deputy abuse by the third party's "
                "other tenants."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Add a Condition requiring a unique sts:ExternalId (agreed with "
                "the trusted third party), or require MFA, on the cross-account "
                "trust statement."
            ),
            tags=frozenset(
                {"iam", "trust-policy", "cross-account", "confused-deputy", "aws"}
            ),
        )
