"""RDS-007: Automated backups are not replicated to another region.

``aws_db_instance_automated_backups_replication`` copies an instance's automated
backups into a second region, so a region-wide outage — or a compromise that
deletes backups in the primary region — still leaves a recoverable copy
elsewhere. Without it, all recovery points live in one region and share its fate.

This is a resilience / disaster-recovery control (LOW). The rule walks the graph
for an ``aws_db_instance_automated_backups_replication`` that references the
instance; finding none, it flags the instance. (Only correlates resources defined
in the same configuration.)
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class RDSNoCrossRegionBackup:
    """RDS-007: instance has no automated-backups replication."""

    rule_id = "RDS-007"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_db_instance":
            return []

        if self._has_replication(node, graph):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="RDS automated backups are not replicated cross-region",
                description=(
                    "No aws_db_instance_automated_backups_replication references "
                    "this instance, so its automated backups live only in the "
                    "primary region. A regional outage or backup deletion leaves no "
                    "recoverable copy elsewhere."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add an aws_db_instance_automated_backups_replication targeting "
                    "this instance to copy automated backups to a second region."
                ),
                tags=frozenset(
                    {"rds", "backup", "cross-region", "disaster-recovery", "aws"}
                ),
            )
        ]

    @staticmethod
    def _has_replication(node: IaCNode, graph: ResourceGraph) -> bool:
        for edge in graph.incoming(node.node_id):
            source = graph.get_node(edge.source)
            if (
                source is not None
                and source.resource_type
                == "aws_db_instance_automated_backups_replication"
            ):
                return True
        return False
