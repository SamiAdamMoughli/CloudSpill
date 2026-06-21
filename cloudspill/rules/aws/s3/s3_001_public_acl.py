"""S3-001: Bucket has a public ACL.

A canned ACL of ``public-read`` or ``public-read-write`` makes a bucket's objects
readable (and, for read-write, writable) by anyone on the internet — the classic
S3 data-leak. The ACL may be set inline on the legacy ``aws_s3_bucket`` (``acl``)
or through a separate ``aws_s3_bucket_acl`` resource.

This rule flags either form when a public canned ACL is applied.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.s3.buckets import PUBLIC_ACLS
from cloudspill.rules.base import register


@register
class S3PublicAcl:
    """S3-001: aws_s3_bucket(_acl) has a public canned ACL."""

    rule_id = "S3-001"
    severity = Severity.CRITICAL

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in ("aws_s3_bucket", "aws_s3_bucket_acl"):
            return []

        acl = str(node.attributes.get("acl", "")).strip().lower()
        if acl not in PUBLIC_ACLS:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="S3 bucket has a public ACL",
                description=(
                    f"A '{acl}' canned ACL is applied, making the bucket's objects "
                    "accessible to anyone on the internet."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set the ACL to 'private' and use a scoped bucket policy; "
                    "attach an aws_s3_bucket_public_access_block with all settings "
                    "true."
                ),
                tags=frozenset({"s3", "acl", "public-access", "data-exposure", "aws"}),
            )
        ]
