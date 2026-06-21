"""S3-003: Bucket has no server-side encryption configured.

A bucket should declare default server-side encryption — inline on the legacy
``aws_s3_bucket`` (``server_side_encryption_configuration``) or via a separate
``aws_s3_bucket_server_side_encryption_configuration`` resource, ideally with a
KMS CMK. Without an explicit configuration there is no controllable key policy or
CMK boundary around the data, and encryption settings are not enforced in code.

This rule flags an ``aws_s3_bucket`` with neither inline encryption nor an
attached encryption-configuration resource.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.s3.buckets import has_attached
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register


@register
class S3NoEncryption:
    """S3-003: bucket has no SSE configuration."""

    rule_id = "S3-003"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_s3_bucket":
            return []
        if as_blocks(node.attributes.get("server_side_encryption_configuration")):
            return []
        if has_attached(
            node, graph, "aws_s3_bucket_server_side_encryption_configuration"
        ):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="S3 bucket has no server-side encryption configured",
                description=(
                    "This aws_s3_bucket declares no default server-side encryption "
                    "(inline or via aws_s3_bucket_server_side_encryption_"
                    "configuration), so there is no controllable CMK boundary "
                    "around its data and encryption is not enforced in code."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add an aws_s3_bucket_server_side_encryption_configuration with "
                    "aws:kms and a customer-managed kms_master_key_id."
                ),
                tags=frozenset({"s3", "encryption", "data-at-rest", "kms", "aws"}),
            )
        ]
