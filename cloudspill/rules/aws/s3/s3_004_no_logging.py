"""S3-004: Bucket has no server access logging.

Server access logging records every request made to a bucket — the data needed
to investigate unauthorized access, data exfiltration, or accidental exposure
after the fact. Logging is configured inline on the legacy ``aws_s3_bucket``
(``logging``) or via a separate ``aws_s3_bucket_logging`` resource. Without it,
there is no record of who read or wrote objects.

This rule flags an ``aws_s3_bucket`` with neither inline logging nor an attached
``aws_s3_bucket_logging`` resource.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.s3.buckets import has_attached
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register


@register
class S3NoLogging:
    """S3-004: bucket has no access logging configured."""

    rule_id = "S3-004"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_s3_bucket":
            return []
        if as_blocks(node.attributes.get("logging")):
            return []
        if has_attached(node, graph, "aws_s3_bucket_logging"):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="S3 bucket has no access logging",
                description=(
                    "This aws_s3_bucket has no server access logging (inline or via "
                    "aws_s3_bucket_logging), so there is no record of requests to "
                    "investigate unauthorized access or exfiltration."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add an aws_s3_bucket_logging targeting a dedicated log bucket."
                ),
                tags=frozenset({"s3", "logging", "audit", "detection", "aws"}),
            )
        ]
