"""CLOUDFRONT-003: CloudFront distribution has no AWS WAF web ACL attached.

A CloudFront distribution should sit behind an AWS WAF web ACL for centralized
layer-7 protection (SQL injection, XSS, bad bots, rate-based floods). Unlike
API Gateway, CloudFront binds the web ACL directly through the
``web_acl_id`` attribute on ``aws_cloudfront_distribution`` — a WAFv2 web ACL
ARN, or a WAF Classic web ACL ID. When that attribute is absent or empty, no
WAF is in front of the distribution.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class CloudFrontNoWafAttached:
    """CLOUDFRONT-003: Distribution lacks a WAF web ACL (web_acl_id)."""

    rule_id = "CLOUDFRONT-003"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_cloudfront_distribution":
            return []

        if str(node.attributes.get("web_acl_id", "")).strip():
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="CloudFront distribution has no WAF web ACL attached",
                description=(
                    "web_acl_id is not set on this aws_cloudfront_distribution. "
                    "The distribution has no layer-7 protection and is exposed to "
                    "application-layer attacks and high-volume floods."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set web_acl_id to a WAFv2 web ACL ARN (or a WAF Classic web "
                    "ACL ID) scoped to CloudFront (CLOUDFRONT scope, us-east-1)."
                ),
                tags=frozenset(
                    {"cloudfront", "waf", "security-defense", "layer-7", "aws"}
                ),
            )
        ]
