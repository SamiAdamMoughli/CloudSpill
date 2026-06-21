"""RDS-005: Enhanced monitoring is not enabled.

Enhanced monitoring streams OS-level metrics (per-process CPU, memory, disk, and
network) from the database host at sub-minute granularity, set via
``monitoring_interval`` (seconds; ``0`` means off). It surfaces resource-
exhaustion attacks, runaway queries, and crypto-mining far sooner than the
default CloudWatch instance metrics, shortening detection and response time.

This is a monitoring control (LOW). The rule flags an ``aws_db_instance`` whose
``monitoring_interval`` is ``0`` or unset.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@register
class RDSNoEnhancedMonitoring:
    """RDS-005: monitoring_interval is 0 or unset."""

    rule_id = "RDS-005"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_db_instance":
            return []

        interval = _to_int(node.attributes.get("monitoring_interval"))
        if interval is not None and interval > 0:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="RDS enhanced monitoring is not enabled",
                description=(
                    "monitoring_interval is 0 or unset on this aws_db_instance, so "
                    "OS-level enhanced monitoring is off. Resource-exhaustion "
                    "attacks and runaway processes are detected more slowly."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set monitoring_interval (e.g. 60) and monitoring_role_arn to "
                    "enable enhanced OS-level monitoring."
                ),
                tags=frozenset({"rds", "monitoring", "detection", "database", "aws"}),
            )
        ]
