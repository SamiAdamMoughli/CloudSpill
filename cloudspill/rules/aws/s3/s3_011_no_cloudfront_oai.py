"""S3-011: Bucket serves content directly via S3 website hosting.

``aws_s3_bucket_website_configuration`` turns a bucket into a static website
served straight from S3. That endpoint is HTTP-only (no TLS), requires the bucket
(or its objects) to be public, and bypasses the controls a CDN provides. The
recommended pattern is to keep the bucket private and front it with CloudFront
using an Origin Access Control/Identity (OAC/OAI), which adds HTTPS, WAF, and
private origin access.

This rule flags an ``aws_s3_bucket_website_configuration`` (or the legacy inline
``website`` block on ``aws_s3_bucket``).
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register


@register
class S3WebsiteHostingNoCloudFront:
    """S3-011: bucket uses direct S3 website hosting."""

    rule_id = "S3-011"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        is_website = node.resource_type == "aws_s3_bucket_website_configuration" or (
            node.resource_type == "aws_s3_bucket"
            and bool(as_blocks(node.attributes.get("website")))
        )
        if not is_website:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="S3 bucket serves content directly via website hosting",
                description=(
                    "This bucket is configured for S3 static website hosting, which "
                    "is HTTP-only, requires public access, and bypasses CDN "
                    "controls. It should be private and fronted by CloudFront with "
                    "an Origin Access Control/Identity."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Keep the bucket private (Block Public Access on) and serve it "
                    "through a CloudFront distribution using OAC/OAI with HTTPS."
                ),
                tags=frozenset({"s3", "website-hosting", "cloudfront", "oai", "aws"}),
            )
        ]
