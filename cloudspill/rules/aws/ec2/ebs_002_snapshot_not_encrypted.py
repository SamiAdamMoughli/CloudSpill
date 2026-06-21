"""EBS-002: Copied EBS snapshot is not encrypted.

``aws_ebs_snapshot_copy`` is the point where snapshot encryption can be added or
dropped: it takes an ``encrypted`` flag (and optional ``kms_key_id``) and can
turn an unencrypted source snapshot into an encrypted copy — or, left at its
default, produce another unencrypted snapshot. An unencrypted snapshot is
plaintext data at rest that travels easily (cross-account, cross-region, or
public sharing).

This rule flags an ``aws_ebs_snapshot_copy`` whose ``encrypted`` is not true.
(A plain ``aws_ebs_snapshot`` inherits encryption from its source volume, which
EBS-001 already covers.)
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
class EBSSnapshotNotEncrypted:
    """EBS-002: aws_ebs_snapshot_copy has encrypted not set to true."""

    rule_id = "EBS-002"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_ebs_snapshot_copy":
            return []

        if _is_true(node.attributes.get("encrypted")):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Copied EBS snapshot is not encrypted",
                description=(
                    "encrypted is not true on this aws_ebs_snapshot_copy, so the "
                    "resulting snapshot stores its data in plaintext at rest. "
                    "Snapshots move easily across accounts and regions, widening "
                    "the exposure."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set encrypted = true (with a kms_key_id for a CMK) on the "
                    "snapshot copy."
                ),
                tags=frozenset(
                    {"ebs", "snapshot", "encryption", "data-at-rest", "aws"}
                ),
            )
        ]
