"""EC2-008: Instance does not have detailed monitoring enabled.

With ``monitoring = true`` CloudWatch collects instance metrics at 1-minute
resolution instead of the default 5-minute basic monitoring. Finer-grained
metrics shorten detection and response time for resource-exhaustion attacks,
crypto-mining spikes, and other anomalies, and make autoscaling react sooner.

This is a monitoring control (LOW). The rule flags an ``aws_instance`` whose
``monitoring`` is not true.
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
class EC2DetailedMonitoringDisabled:
    """EC2-008: aws_instance has monitoring not enabled."""

    rule_id = "EC2-008"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_instance":
            return []

        if _is_true(node.attributes.get("monitoring")):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Instance does not have detailed monitoring enabled",
                description=(
                    "monitoring is not true on this aws_instance, so CloudWatch "
                    "collects metrics only at 5-minute resolution. Anomalies such "
                    "as resource-exhaustion or crypto-mining spikes are detected "
                    "more slowly."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set monitoring = true to enable 1-minute detailed CloudWatch "
                    "metrics for the instance."
                ),
                tags=frozenset(
                    {"ec2", "monitoring", "cloudwatch", "detection", "aws"}
                ),
            )
        ]
