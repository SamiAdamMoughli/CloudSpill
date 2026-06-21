"""IAM-004: Privileged policy statement does not enforce MFA.

A high-power Allow statement that has no ``aws:MultiFactorAuthPresent`` condition
grants its access to anyone holding the credentials — so a single phished or
leaked secret immediately yields privileged access, with no second factor in the
way. Sensitive permissions (IAM, STS, and full-wildcard actions) should be gated
on MFA.

To stay low-noise this rule only flags statements that are actually privileged —
those whose actions include ``"*"`` or an ``iam:``/``sts:`` action — and that
carry no MFA condition.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.iam.policy_docs import (
    IDENTITY_POLICY_TYPES,
    as_list,
    identity_statements,
    statement_enforces_mfa,
)
from cloudspill.rules.base import register

_PRIVILEGED_PREFIXES = ("iam:", "sts:")


def _is_privileged(action: str) -> bool:
    lowered = action.strip().lower()
    return lowered == "*" or lowered.startswith(_PRIVILEGED_PREFIXES)


@register
class IAMNoMfaEnforced:
    """IAM-004: privileged Allow statement lacks an MFA condition."""

    rule_id = "IAM-004"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in IDENTITY_POLICY_TYPES:
            return []

        for stmt in identity_statements(node):
            if stmt.get("Effect") != "Allow":
                continue
            actions = [str(a) for a in as_list(stmt.get("Action"))]
            if any(_is_privileged(a) for a in actions) and not statement_enforces_mfa(
                stmt
            ):
                return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Privileged IAM statement does not enforce MFA",
            description=(
                "An Allow statement grants privileged actions (IAM/STS or a "
                "wildcard) without an aws:MultiFactorAuthPresent condition. "
                "Compromised credentials grant this access with no second factor."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Add a Condition requiring aws:MultiFactorAuthPresent = true (or "
                "BoolIfExists) to privileged statements."
            ),
            tags=frozenset({"iam", "mfa", "privileged-access", "condition", "aws"}),
        )
