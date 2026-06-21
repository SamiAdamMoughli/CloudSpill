"""TRAIL-004: CloudTrail is not integrated with CloudWatch Logs.

By default a trail only delivers log files to S3, where they sit until someone
goes looking. Wiring the trail to a CloudWatch Logs group (via
``cloud_watch_logs_group_arn`` plus the delivery role ``cloud_watch_logs_role_arn``)
enables near-real-time monitoring: metric filters and alarms on events like
root usage, IAM policy changes, or console sign-in failures, instead of
after-the-fact log review.

When ``cloud_watch_logs_group_arn`` is absent or empty there is no CloudWatch
integration, so no real-time alerting can be built on the trail. This rule
flags that case.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class CloudTrailNoCloudWatchLogs:
    """TRAIL-004: aws_cloudtrail has no cloud_watch_logs_group_arn."""

    rule_id = "TRAIL-004"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_cloudtrail":
            return []

        if str(node.attributes.get("cloud_watch_logs_group_arn", "")).strip():
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="CloudTrail is not integrated with CloudWatch Logs",
                description=(
                    "cloud_watch_logs_group_arn is not set on this aws_cloudtrail, "
                    "so events are delivered only to S3. Without a CloudWatch Logs "
                    "group there are no metric filters or alarms, so suspicious "
                    "activity is detected only by after-the-fact log review."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set cloud_watch_logs_group_arn to a CloudWatch Logs group ARN "
                    "and cloud_watch_logs_role_arn to a role that lets CloudTrail "
                    "deliver events, then add metric filters/alarms on key events."
                ),
                tags=frozenset(
                    {"cloudtrail", "logging", "monitoring", "cloudwatch", "aws"}
                ),
            )
        ]
