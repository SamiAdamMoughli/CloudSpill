"""RDS-006: Database instance is not Multi-AZ.

``multi_az = true`` maintains a synchronous standby in a second Availability
Zone and fails over automatically if the primary's AZ, host, or storage fails.
A single-AZ instance has no such redundancy: an AZ outage or host failure takes
the database down until it is manually restored, and there is no hot standby for
patching with minimal downtime.

This is a resilience control (LOW). The rule flags an ``aws_db_instance`` whose
``multi_az`` is not true. (Aurora clusters are inherently multi-AZ and are not
checked.)
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
class RDSMultiAzDisabled:
    """RDS-006: aws_db_instance has multi_az not true."""

    rule_id = "RDS-006"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_db_instance":
            return []

        if _is_true(node.attributes.get("multi_az")):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="RDS instance is not Multi-AZ",
                description=(
                    "multi_az is not true on this aws_db_instance, so there is no "
                    "standby in a second Availability Zone. An AZ or host failure "
                    "causes downtime until the database is manually restored."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set multi_az = true on production instances for automatic "
                    "failover to a standby Availability Zone."
                ),
                tags=frozenset(
                    {"rds", "multi-az", "high-availability", "resilience", "aws"}
                ),
            )
        ]
