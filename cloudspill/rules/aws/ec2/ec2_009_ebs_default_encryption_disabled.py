"""EC2-009: Account-wide EBS default encryption is turned off.

``aws_ebs_encryption_by_default`` is a region-level switch that forces every new
EBS volume and snapshot to be encrypted, regardless of what individual resource
definitions specify. It is the backstop that catches volumes someone forgot to
encrypt. Declaring this resource with ``enabled = false`` actively disables that
backstop for the whole region.

This rule flags ``aws_ebs_encryption_by_default`` only when ``enabled`` is
explicitly false — a present-and-true (or absent) setting is the safe state.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class EC2EbsDefaultEncryptionDisabled:
    """EC2-009: aws_ebs_encryption_by_default has enabled = false."""

    rule_id = "EC2-009"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_ebs_encryption_by_default":
            return []

        if not self._explicitly_disabled(node):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Account-wide EBS default encryption is disabled",
                description=(
                    "aws_ebs_encryption_by_default sets enabled = false, turning "
                    "off the region-wide backstop that forces every new EBS volume "
                    "and snapshot to be encrypted. Any volume not explicitly "
                    "encrypted will be created in plaintext."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set enabled = true (or remove the resource) so EBS default "
                    "encryption stays on for the region."
                ),
                tags=frozenset(
                    {"ec2", "ebs", "encryption", "account-baseline", "aws"}
                ),
            )
        ]

    @staticmethod
    def _explicitly_disabled(node: IaCNode) -> bool:
        if "enabled" not in node.attributes:
            return False
        value = node.attributes["enabled"]
        if isinstance(value, bool):
            return value is False
        return str(value).strip().lower() == "false"
