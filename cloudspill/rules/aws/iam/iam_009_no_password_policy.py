"""IAM-009: Account password policy is weak.

``aws_iam_account_password_policy`` sets the account's console-password rules. A
policy that allows short passwords, omits character-class requirements, or never
expires passwords / allows reuse weakens every IAM user's console credential and
eases brute-force and credential-stuffing attacks.

This rule flags an ``aws_iam_account_password_policy`` that is materially weak:
``minimum_password_length`` under 14, any character-class requirement left off,
or no ``max_password_age`` / ``password_reuse_prevention`` set. (Absence of the
resource entirely is an account-baseline gap this per-resource rule cannot see.)
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_REQUIRED_FLAGS = (
    "require_uppercase_characters",
    "require_lowercase_characters",
    "require_numbers",
    "require_symbols",
)


def _is_true(value: Any) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() == "true"


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@register
class IAMWeakPasswordPolicy:
    """IAM-009: aws_iam_account_password_policy is weak."""

    rule_id = "IAM-009"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_iam_account_password_policy":
            return []

        weaknesses = self._weaknesses(node)
        if not weaknesses:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="IAM account password policy is weak",
                description=(
                    "The account password policy is weak: "
                    + "; ".join(weaknesses)
                    + ". This weakens every IAM user's console credential against "
                    "brute-force and reuse attacks."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set minimum_password_length >= 14, require all character "
                    "classes, and set max_password_age and "
                    "password_reuse_prevention."
                ),
                tags=frozenset({"iam", "password-policy", "account-baseline", "aws"}),
            )
        ]

    @staticmethod
    def _weaknesses(node: IaCNode) -> list[str]:
        attrs = node.attributes
        issues: list[str] = []

        length = _to_int(attrs.get("minimum_password_length"))
        if length is None or length < 14:
            issues.append("minimum_password_length below 14")

        for flag in _REQUIRED_FLAGS:
            if not _is_true(attrs.get(flag)):
                issues.append(f"{flag} not enabled")

        if not _to_int(attrs.get("max_password_age")):
            issues.append("max_password_age not set")
        if not _to_int(attrs.get("password_reuse_prevention")):
            issues.append("password_reuse_prevention not set")

        return issues
