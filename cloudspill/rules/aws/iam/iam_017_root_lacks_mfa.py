"""IAM-017: Account root is trusted without requiring MFA.

The account root principal (``arn:aws:iam::<account-id>:root``) should never be
trusted to assume a role or access a resource without a second factor. A trust
or resource statement that grants to ``:root`` with no
``aws:MultiFactorAuthPresent`` condition means a single set of credentials in
that account is enough — there is no MFA gate on a maximally broad principal.

This rule flags an ``aws_iam_role`` trust policy (or an identity policy carrying
a Principal) that grants to an account-root principal without an MFA condition.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.iam.policy_docs import (
    IDENTITY_POLICY_TYPES,
    aws_principals,
    identity_statements,
    statement_enforces_mfa,
    trust_statements,
)
from cloudspill.rules.base import register


def _statements(node: IaCNode) -> list[dict[str, Any]]:
    if node.resource_type == "aws_iam_role":
        return trust_statements(node)
    if node.resource_type in IDENTITY_POLICY_TYPES:
        return identity_statements(node)
    return []


@register
class IAMRootLacksMfa:
    """IAM-017: account-root principal trusted with no MFA condition."""

    rule_id = "IAM-017"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        for stmt in _statements(node):
            if stmt.get("Effect") != "Allow":
                continue
            is_root = any(p.rstrip("/").endswith(":root") for p in aws_principals(stmt))
            if is_root and not statement_enforces_mfa(stmt):
                return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Account root is trusted without requiring MFA",
            description=(
                "A statement grants to the account-root principal (:root) with no "
                "aws:MultiFactorAuthPresent condition. The broadest possible "
                "principal is trusted with no second factor."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Require MFA via a Condition (aws:MultiFactorAuthPresent = true), "
                "and prefer naming specific role/user ARNs instead of :root."
            ),
            tags=frozenset({"iam", "root-principal", "mfa", "trust-policy", "aws"}),
        )
