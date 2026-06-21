"""SECRETS-003: Secret resource policy grants broad cross-account access.

An ``aws_secretsmanager_secret_policy`` controls who, outside the secret's own
account roles, can read it. An ``Allow`` statement with a wildcard principal
(``"*"`` / ``{"AWS": "*"}``) or another account's root with no constraining
``Condition`` exposes the secret value — database passwords, API keys — to
principals well beyond the owning account.

This rule flags an ``aws_secretsmanager_secret_policy`` whose policy has an Allow
statement with a wildcard or cross-account principal and no Condition.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.policy import extract_statements, is_wildcard_principal
from cloudspill.rules.base import register


def _principal_arns(stmt: dict) -> list[str]:
    principal = stmt.get("Principal")
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        return [str(v) for v in (aws if isinstance(aws, list) else [aws]) if v]
    return []


def _is_cross_account(stmt: dict) -> bool:
    return any(p.startswith("arn:aws:iam::") for p in _principal_arns(stmt))


@register
class SecretsCrossAccountAccess:
    """SECRETS-003: secret policy allows wildcard/cross-account principal."""

    rule_id = "SECRETS-003"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_secretsmanager_secret_policy":
            return []

        for stmt in extract_statements(node.attributes.get("policy", "")):
            if stmt.get("Effect") != "Allow" or stmt.get("Condition"):
                continue
            if is_wildcard_principal(stmt.get("Principal")) or _is_cross_account(stmt):
                return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Secret resource policy grants broad cross-account access",
            description=(
                "An Allow statement in this secret's resource policy grants a "
                "wildcard or cross-account principal with no Condition, exposing "
                "the secret value beyond the owning account's roles."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Scope the policy Principal to specific role ARNs that need the "
                "secret, and add a Condition (e.g. aws:PrincipalOrgID) for any "
                "cross-account access."
            ),
            tags=frozenset(
                {"secrets-manager", "resource-policy", "cross-account", "public-access", "aws"}
            ),
        )
