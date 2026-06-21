"""RDS-004: Automated backups are disabled.

``backup_retention_period`` controls how many days of automated backups RDS
keeps; setting it to ``0`` turns automated backups (and point-in-time recovery)
off entirely. The database then has no managed restore point, so corruption,
accidental deletion, or ransomware leaves nothing to recover from.

This is a resilience control (LOW). The rule flags an ``aws_db_instance`` or
``aws_rds_cluster`` whose ``backup_retention_period`` is explicitly ``0`` (an
unset value uses the engine default, which is non-zero).
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_RDS_TYPES = frozenset({"aws_db_instance", "aws_rds_cluster"})


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@register
class RDSBackupsDisabled:
    """RDS-004: backup_retention_period set to 0."""

    rule_id = "RDS-004"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _RDS_TYPES:
            return []

        if "backup_retention_period" not in node.attributes:
            return []  # unset → engine default (non-zero)
        if _to_int(node.attributes["backup_retention_period"]) != 0:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="RDS automated backups are disabled",
                description=(
                    "backup_retention_period is 0 on this database, disabling "
                    "automated backups and point-in-time recovery. There is no "
                    "managed restore point after corruption, deletion, or "
                    "ransomware."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set backup_retention_period to a non-zero value (e.g. 7-35 "
                    "days) appropriate to your recovery requirements."
                ),
                tags=frozenset(
                    {"rds", "backup", "resilience", "recovery", "aws"}
                ),
            )
        ]
