"""TRAIL-001: CloudTrail trail has logging disabled.

``aws_cloudtrail`` carries an ``enable_logging`` argument that controls whether
the trail actually delivers events. It defaults to ``true``, so a trail is
recording unless logging is *explicitly* turned off. When ``enable_logging =
false`` the trail still exists in the configuration — passing a superficial
"a trail is defined" check — but captures nothing, leaving the account with no
audit record of API activity.

This rule flags only the explicit ``enable_logging = false`` case. A missing
attribute is the secure default (logging on) and is not flagged.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class CloudTrailLoggingDisabled:
    """TRAIL-001: aws_cloudtrail has enable_logging explicitly set to false."""

    rule_id = "TRAIL-001"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_cloudtrail":
            return []

        if not self._is_logging_disabled(node):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="CloudTrail trail has logging disabled",
                description=(
                    "enable_logging is set to false on this aws_cloudtrail. The "
                    "trail is defined but delivers no events, so API activity in "
                    "the account goes unrecorded and security investigations have "
                    "no audit trail to work from."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set enable_logging = true (or remove the argument to use the "
                    "secure default) so the trail records management and data "
                    "events."
                ),
                tags=frozenset(
                    {"cloudtrail", "logging", "audit", "visibility", "aws"}
                ),
            )
        ]

    @staticmethod
    def _is_logging_disabled(node: IaCNode) -> bool:
        """True only when enable_logging is explicitly a false-y value."""
        if "enable_logging" not in node.attributes:
            return False  # absent → defaults to true (logging on)
        value = node.attributes["enable_logging"]
        if isinstance(value, bool):
            return value is False
        return str(value).strip().lower() == "false"
