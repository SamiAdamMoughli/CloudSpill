"""S3-002: Block Public Access is not fully enabled.

``aws_s3_bucket_public_access_block`` is the account/bucket-level backstop that
overrides public ACLs and policies. All four settings — ``block_public_acls``,
``block_public_policy``, ``ignore_public_acls``, ``restrict_public_buckets`` —
should be true. Any one set false leaves a gap through which a public ACL or
policy can still expose the bucket.

This rule flags an ``aws_s3_bucket_public_access_block`` with any of the four
settings not true.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.s3.buckets import is_true
from cloudspill.rules.base import register

_PAB_SETTINGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)


@register
class S3BlockPublicAccessDisabled:
    """S3-002: a public-access-block setting is not true."""

    rule_id = "S3-002"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_s3_bucket_public_access_block":
            return []

        disabled = [s for s in _PAB_SETTINGS if not is_true(node.attributes.get(s))]
        if not disabled:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="S3 Block Public Access is not fully enabled",
                description=(
                    "These public-access-block settings are not true: "
                    + ", ".join(disabled)
                    + ". A public ACL or policy can still expose the bucket "
                    "through the open setting(s)."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set block_public_acls, block_public_policy, ignore_public_acls "
                    "and restrict_public_buckets all to true."
                ),
                tags=frozenset({"s3", "public-access-block", "public-access", "aws"}),
            )
        ]
