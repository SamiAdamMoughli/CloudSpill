"""S3-009: Bucket has no object lock (WORM) configured.

Object Lock enforces write-once-read-many (WORM) retention so objects cannot be
deleted or overwritten until their retention period expires — the strongest
defence against ransomware and malicious or accidental tampering of critical
data (logs, backups, compliance records). It must be enabled at bucket creation
(``object_lock_enabled``) and governed by an
``aws_s3_bucket_object_lock_configuration``.

This is a resilience / compliance control (LOW). The rule flags an
``aws_s3_bucket`` that neither sets ``object_lock_enabled`` nor has an attached
object-lock configuration.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.s3.buckets import has_attached, is_true
from cloudspill.rules.base import register


@register
class S3NoObjectLock:
    """S3-009: bucket has no object lock configured."""

    rule_id = "S3-009"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_s3_bucket":
            return []
        if is_true(node.attributes.get("object_lock_enabled")):
            return []
        if has_attached(node, graph, "aws_s3_bucket_object_lock_configuration"):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="S3 bucket has no object lock (WORM) configured",
                description=(
                    "This aws_s3_bucket has no Object Lock, so objects can be "
                    "overwritten or deleted at will. For logs, backups, or "
                    "compliance data this removes the WORM protection against "
                    "ransomware and tampering."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Create the bucket with object_lock_enabled = true and add an "
                    "aws_s3_bucket_object_lock_configuration with a retention rule "
                    "for data that must be immutable."
                ),
                tags=frozenset({"s3", "object-lock", "worm", "ransomware", "aws"}),
            )
        ]
