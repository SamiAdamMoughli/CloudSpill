"""GD-002: GuardDuty S3 protection is disabled.

S3 protection analyses S3 data-plane events (GetObject, PutObject, …) for
suspicious access patterns — mass downloads, access from anomalous principals or
locations, and exfiltration. It is enabled either by the modern
``aws_guardduty_detector_feature`` (``name = "S3_DATA_EVENTS"``) or the legacy
``datasources { s3_logs { enable = true } }`` block.

This rule flags the feature being set to DISABLED, or the legacy s3_logs
data source being explicitly disabled.
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
class GuardDutyS3ProtectionDisabled:
    """GD-002: GuardDuty S3 data-event protection is off."""

    rule_id = "GD-002"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if detector_feature_disabled(node, "S3_DATA_EVENTS") or legacy_datasource_disabled(
            node, "s3_logs"
        ):
            return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="GuardDuty S3 protection is disabled",
            description=(
                "GuardDuty S3 protection (S3_DATA_EVENTS / s3_logs) is disabled, "
                "so suspicious S3 data-plane activity such as mass downloads or "
                "exfiltration from anomalous principals is not detected."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                'Enable the S3_DATA_EVENTS detector feature (status = "ENABLED") '
                "or set datasources { s3_logs { enable = true } }."
            ),
            tags=frozenset(
                {"guardduty", "s3", "threat-detection", "data-exfiltration", "aws"}
            ),
        )
