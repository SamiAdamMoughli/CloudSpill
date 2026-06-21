"""GD-001: GuardDuty detector is disabled.

``aws_guardduty_detector`` is the switch that turns on continuous threat
detection for a region — analysing CloudTrail, VPC flow logs, and DNS logs for
recon, credential abuse, crypto-mining, and exfiltration. Its ``enable``
argument defaults to true, so declaring the detector with ``enable = false``
deliberately turns the region's primary threat-detection capability off.

This rule flags an ``aws_guardduty_detector`` whose ``enable`` is explicitly
false.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class GuardDutyDisabled:
    """GD-001: aws_guardduty_detector has enable = false."""

    rule_id = "GD-001"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_guardduty_detector":
            return []

        if not self._explicitly_disabled(node):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="GuardDuty detector is disabled",
                description=(
                    "aws_guardduty_detector sets enable = false, turning off "
                    "continuous threat detection for the region. Reconnaissance, "
                    "credential abuse, crypto-mining, and exfiltration go "
                    "undetected."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set enable = true (or remove the argument) so the GuardDuty "
                    "detector stays active in the region."
                ),
                tags=frozenset({"guardduty", "threat-detection", "monitoring", "aws"}),
            )
        ]

    @staticmethod
    def _explicitly_disabled(node: IaCNode) -> bool:
        if "enable" not in node.attributes:
            return False
        value = node.attributes["enable"]
        if isinstance(value, bool):
            return value is False
        return str(value).strip().lower() == "false"
