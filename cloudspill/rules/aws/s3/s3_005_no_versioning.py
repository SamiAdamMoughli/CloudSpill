"""S3-005: Bucket does not have versioning enabled.

Versioning keeps prior copies of every object, so an overwrite or delete —
accidental, or a ransomware-style mass overwrite — can be rolled back. It is the
foundation for recovery on S3 (and a prerequisite for MFA delete and replication).
Versioning is set inline on the legacy ``aws_s3_bucket`` (``versioning``) or via a
separate ``aws_s3_bucket_versioning`` resource.

This rule flags an ``aws_s3_bucket`` with neither inline versioning enabled nor an
attached ``aws_s3_bucket_versioning`` resource.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.s3.buckets import has_attached, is_true
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register


@register
class S3NoVersioning:
    """S3-005: bucket has no versioning enabled."""

    rule_id = "S3-005"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_s3_bucket":
            return []
        if any(
            is_true(b.get("enabled"))
            for b in as_blocks(node.attributes.get("versioning"))
        ):
            return []
        if has_attached(node, graph, "aws_s3_bucket_versioning"):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="S3 bucket does not have versioning enabled",
                description=(
                    "This aws_s3_bucket has no versioning (inline or via "
                    "aws_s3_bucket_versioning), so overwritten or deleted objects "
                    "cannot be recovered — including from a ransomware-style mass "
                    "overwrite."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add an aws_s3_bucket_versioning with versioning_configuration "
                    'status = "Enabled".'
                ),
                tags=frozenset({"s3", "versioning", "resilience", "recovery", "aws"}),
            )
        ]
