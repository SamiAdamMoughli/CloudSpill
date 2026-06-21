"""IAM-008: Static IAM access key defined.

``aws_iam_access_key`` creates a long-lived programmatic credential for an IAM
user. These keys do not expire and are not rotated automatically, so they age in
place and become one of the most common breach vectors — leaked in code, CI
logs, or laptops, and valid indefinitely until someone manually rotates them.

This is the static-key counterpart to IAM-014 (console login profiles). The
rule flags any ``aws_iam_access_key`` resource; prefer short-lived role
credentials or IAM Identity Center wherever possible.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class IAMStaticAccessKey:
    """IAM-008: an aws_iam_access_key (long-lived static key) is defined."""

    rule_id = "IAM-008"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_iam_access_key":
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Static IAM access key defined",
                description=(
                    "This aws_iam_access_key is a long-lived programmatic "
                    "credential. It does not expire or rotate on its own, so it "
                    "ages in place and stays valid indefinitely if leaked."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Replace static keys with short-lived role credentials (IAM "
                    "roles, instance profiles, or IAM Identity Center); if "
                    "unavoidable, enforce regular rotation."
                ),
                tags=frozenset(
                    {"iam", "access-key", "long-lived-credentials", "rotation", "aws"}
                ),
            )
        ]
