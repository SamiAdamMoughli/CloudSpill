"""IAM-014: Long-lived console credential (login profile) defined.

``aws_iam_user_login_profile`` gives an IAM user a console password — a
long-term human credential tied to a standalone IAM identity. These accounts
accumulate, are hard to govern centrally, and (without enforced MFA) are a
phishing target. Modern guidance is to manage human access through IAM Identity
Center / federation rather than per-user IAM passwords.

This is the console-credential counterpart to IAM-008 (static access keys). The
rule flags any ``aws_iam_user_login_profile`` resource.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class IAMLongTermCredentials:
    """IAM-014: an aws_iam_user_login_profile is defined."""

    rule_id = "IAM-014"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_iam_user_login_profile":
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Long-lived console credential (login profile) defined",
                description=(
                    "This aws_iam_user_login_profile gives an IAM user a console "
                    "password — a standalone long-term human credential that is "
                    "hard to govern centrally and is a phishing target without "
                    "enforced MFA."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Manage human access through IAM Identity Center / federation "
                    "instead of per-user IAM passwords; where unavoidable, enforce "
                    "MFA and rotation."
                ),
                tags=frozenset(
                    {
                        "iam",
                        "login-profile",
                        "long-lived-credentials",
                        "federation",
                        "aws",
                    }
                ),
            )
        ]
