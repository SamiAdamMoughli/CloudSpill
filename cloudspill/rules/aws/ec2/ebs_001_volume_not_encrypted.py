"""EBS-001: EBS volume is not encrypted.

``aws_ebs_volume`` takes an ``encrypted`` flag. An unencrypted volume stores its
data in plaintext at rest, so anyone who can read a snapshot of it, or attach a
detached copy, reads the data directly. Encryption (ideally with a
customer-managed ``kms_key_id``) makes that data useless without the key.

This rule flags an ``aws_ebs_volume`` whose ``encrypted`` is not true.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


def _is_true(value: object) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() == "true"


@register
class EBSVolumeNotEncrypted:
    """EBS-001: aws_ebs_volume has encrypted not set to true."""

    rule_id = "EBS-001"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_ebs_volume":
            return []

        if _is_true(node.attributes.get("encrypted")):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="EBS volume is not encrypted",
                description=(
                    "encrypted is not true on this aws_ebs_volume, so its data is "
                    "stored in plaintext at rest and is exposed through any "
                    "snapshot or detached-volume access."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set encrypted = true (optionally with a customer-managed "
                    "kms_key_id) on the volume."
                ),
                tags=frozenset(
                    {"ebs", "encryption", "data-at-rest", "aws"}
                ),
            )
        ]
