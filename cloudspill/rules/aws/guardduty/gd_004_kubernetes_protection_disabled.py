"""GD-004: GuardDuty Kubernetes (EKS) audit-log protection is disabled.

Kubernetes protection ingests EKS control-plane audit logs and detects suspicious
API activity — anonymous access, privilege escalation, exec into pods, and use of
compromised credentials. It is enabled either by the modern
``aws_guardduty_detector_feature`` (``name = "EKS_AUDIT_LOGS"``) or the legacy
``datasources { kubernetes { audit_logs { enable = true } } }`` block.

This rule flags the feature being DISABLED, or the legacy audit_logs data source
being explicitly disabled.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.guardduty.features import (
    detector_feature_disabled,
    legacy_datasource_disabled,
)
from cloudspill.rules.base import register


@register
class GuardDutyKubernetesProtectionDisabled:
    """GD-004: GuardDuty EKS audit-log protection is off."""

    rule_id = "GD-004"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if detector_feature_disabled(
            node, "EKS_AUDIT_LOGS"
        ) or legacy_datasource_disabled(node, "kubernetes", "audit_logs"):
            return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="GuardDuty Kubernetes audit-log protection is disabled",
            description=(
                "GuardDuty Kubernetes protection (EKS_AUDIT_LOGS) is disabled, so "
                "EKS control-plane audit logs are not analysed for anonymous "
                "access, privilege escalation, or pod-exec abuse."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                'Enable the EKS_AUDIT_LOGS detector feature (status = "ENABLED") '
                "or set datasources { kubernetes { audit_logs { enable = true } } }."
            ),
            tags=frozenset(
                {"guardduty", "kubernetes", "eks", "threat-detection", "aws"}
            ),
        )
