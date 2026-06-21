"""S3-006: Bucket has no resource policy.

A bucket policy is the resource-level access control for S3 — it is where you
explicitly state who may access the bucket and, crucially, add the Deny
statements that enforce TLS-only and encrypted access regardless of identity
policies. A bucket with no policy relies entirely on IAM and ACLs, leaving no
resource-side allow-list or Deny backstop.

This is a defence-in-depth control (LOW). The rule flags an ``aws_s3_bucket`` with
no attached ``aws_s3_bucket_policy`` (and no inline ``policy``).
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.s3.buckets import has_attached
from cloudspill.rules.base import register


@register
class S3NoBucketPolicy:
    """S3-006: bucket has no resource policy."""

    rule_id = "S3-006"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_s3_bucket":
            return []
        if str(node.attributes.get("policy", "")).strip():
            return []
        if has_attached(node, graph, "aws_s3_bucket_policy"):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="S3 bucket has no resource policy",
                description=(
                    "This aws_s3_bucket has no bucket policy, so access is governed "
                    "only by IAM and ACLs. There is no resource-side allow-list or "
                    "Deny backstop to enforce TLS-only/encrypted access."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Attach an aws_s3_bucket_policy that scopes access and adds "
                    "Deny statements for non-TLS and unencrypted requests."
                ),
                tags=frozenset({"s3", "bucket-policy", "defense-in-depth", "aws"}),
            )
        ]
