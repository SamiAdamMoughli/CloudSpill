"""EBS-004: EBS volume is not covered by an AWS Backup plan.

An ``aws_backup_selection`` lists the resources a backup plan protects via its
``resources`` ARNs. An ``aws_ebs_volume`` that no selection references has no
managed, scheduled backups, so there is no clean restore point after corruption,
accidental deletion, or ransomware — point-in-time recovery of block storage
depends on those snapshots existing.

This rule walks the graph for an incoming edge from an
``aws_backup_selection`` to the volume; finding none, it flags the volume. It
is a resilience control (LOW) and fires only on volumes defined in the same
configuration (a selection referencing the volume only by a literal ARN string
cannot be correlated).
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class EBSVolumeNoBackup:
    """EBS-004: aws_ebs_volume not referenced by any aws_backup_selection."""

    rule_id = "EBS-004"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_ebs_volume":
            return []

        if self._has_backup_selection(node, graph):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="EBS volume is not covered by an AWS Backup plan",
                description=(
                    "No aws_backup_selection references this aws_ebs_volume, so it "
                    "has no managed, scheduled backups. There is no guaranteed "
                    "restore point after corruption, deletion, or ransomware."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add the volume's ARN to an aws_backup_selection tied to a "
                    "backup plan with an appropriate schedule and retention."
                ),
                tags=frozenset({"ebs", "backup", "resilience", "recovery", "aws"}),
            )
        ]

    @staticmethod
    def _has_backup_selection(node: IaCNode, graph: ResourceGraph) -> bool:
        for edge in graph.incoming(node.node_id):
            source = graph.get_node(edge.source)
            if source is not None and source.resource_type == "aws_backup_selection":
                return True
        return False
