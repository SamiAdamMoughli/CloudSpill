"""CLOUDFRONT-004: CloudFront distribution has access logging disabled.

A distribution should write standard access logs to S3 via a ``logging_config``
block whose ``bucket`` names the destination. Without it there is no record of
who requested what — losing the audit trail needed to investigate abuse,
analyze traffic, and meet compliance logging requirements.

A ``logging_config`` block with no ``bucket`` counts as disabled. python-hcl2
may surface the block as a dict, a single-element list of dicts, or — for an
inline block — as a child node, so all three shapes are checked.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_LOGGING_KEY = "logging_config"


@register
class CloudFrontLoggingDisabled:
    """CLOUDFRONT-004: Distribution has no logging_config with a bucket."""

    rule_id = "CLOUDFRONT-004"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_cloudfront_distribution":
            return []

        if self._has_logging(node):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="CloudFront distribution has access logging disabled",
                description=(
                    "No logging_config block with a destination bucket is "
                    "configured on this distribution. Viewer requests are not "
                    "logged, leaving no access audit trail."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add a logging_config block with bucket set to an S3 bucket "
                    "(e.g. my-logs.s3.amazonaws.com) to capture standard logs."
                ),
                tags=frozenset(
                    {"cloudfront", "logging", "audit", "observability", "aws"}
                ),
            )
        ]

    @staticmethod
    def _has_logging(node: IaCNode) -> bool:
        """True if a logging_config block names a destination bucket."""
        blocks: list[dict[str, Any]] = []
        value = node.attributes.get(_LOGGING_KEY)
        if isinstance(value, list):
            blocks.extend(b for b in value if isinstance(b, dict))
        elif isinstance(value, dict):
            blocks.append(value)
        blocks.extend(
            c.attributes for c in node.children if c.resource_type == _LOGGING_KEY
        )

        return any(str(b.get("bucket", "")).strip() for b in blocks)
