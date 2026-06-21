"""GD-005: GuardDuty runtime monitoring is disabled.

Runtime monitoring puts a lightweight GuardDuty agent on EC2, ECS, and EKS
workloads to observe process, file, and network behaviour at runtime — catching
in-memory and on-host threats (reverse shells, crypto-miners, container escapes)
that log-based detection misses. It is enabled through
``aws_guardduty_detector_feature`` with ``name = "RUNTIME_MONITORING"`` (there
is no legacy datasources equivalent).

This rule flags the RUNTIME_MONITORING feature being set to DISABLED.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.guardduty.features import detector_feature_disabled
from cloudspill.rules.base import register


@register
class GuardDutyRuntimeMonitoringDisabled:
    """GD-005: GuardDuty RUNTIME_MONITORING feature is off."""

    rule_id = "GD-005"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if detector_feature_disabled(node, "RUNTIME_MONITORING"):
            return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="GuardDuty runtime monitoring is disabled",
            description=(
                "The RUNTIME_MONITORING detector feature is disabled, so GuardDuty "
                "has no on-host visibility into process, file, and network "
                "behaviour. Runtime threats such as reverse shells, crypto-miners, "
                "and container escapes go undetected."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Enable the RUNTIME_MONITORING detector feature (status = "
                '"ENABLED") and deploy the GuardDuty agent to your workloads.'
            ),
            tags=frozenset(
                {"guardduty", "runtime-monitoring", "threat-detection", "ec2", "aws"}
            ),
        )
