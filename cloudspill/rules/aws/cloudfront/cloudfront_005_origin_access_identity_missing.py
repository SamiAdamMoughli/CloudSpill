"""CLOUDFRONT-005: S3 origin reachable without Origin Access Control/Identity.

When CloudFront serves content from an S3 bucket, the bucket should be private
and readable only by CloudFront. That is achieved with either:

* **Origin Access Control (OAC)** — the modern mechanism: the ``origin`` block
  sets ``origin_access_control_id`` referencing an
  ``aws_cloudfront_origin_access_control``; or
* **Origin Access Identity (OAI)** — the legacy mechanism: the origin's
  ``s3_origin_config`` block sets a non-empty ``origin_access_identity``.

An S3 origin with neither forces the bucket to be publicly readable so viewers
can reach objects directly, bypassing CloudFront (and its WAF, logging, and TLS
policy).

Only S3 origins are evaluated. An origin is treated as S3 when it has an
``s3_origin_config`` block or its ``domain_name`` points at S3; ``origin``
blocks with a ``custom_origin_config`` are non-S3 and skipped.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register


@register
class CloudFrontOriginAccessIdentityMissing:
    """CLOUDFRONT-005: S3 origin has no OAC or OAI."""

    rule_id = "CLOUDFRONT-005"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_cloudfront_distribution":
            return []

        for origin in self._origins(node):
            if not self._is_s3_origin(origin):
                continue
            if self._is_protected(origin):
                continue
            return [self._finding(node)]
        return []

    @staticmethod
    def _origins(node: IaCNode) -> list[dict[str, Any]]:
        """All origin blocks, however hcl2 shaped them (attr list/dict or child)."""
        blocks = as_blocks(node.attributes.get("origin"))
        blocks.extend(
            c.attributes for c in node.children if c.resource_type == "origin"
        )
        return blocks

    @staticmethod
    def _is_s3_origin(origin: dict[str, Any]) -> bool:
        if "s3_origin_config" in origin:
            return True
        if "custom_origin_config" in origin:
            return False
        domain = str(origin.get("domain_name", "")).lower()
        return ".s3." in domain or ".s3-" in domain or domain.endswith("s3.amazonaws.com")

    @staticmethod
    def _is_protected(origin: dict[str, Any]) -> bool:
        # Modern OAC: an origin_access_control_id on the origin.
        if str(origin.get("origin_access_control_id", "")).strip():
            return True
        # Legacy OAI: a non-empty origin_access_identity in s3_origin_config.
        for cfg in as_blocks(origin.get("s3_origin_config")):
            if str(cfg.get("origin_access_identity", "")).strip():
                return True
        return False

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="CloudFront S3 origin has no Origin Access Control/Identity",
            description=(
                "An S3 origin is configured without Origin Access Control "
                "(origin_access_control_id) or a legacy Origin Access Identity "
                "(s3_origin_config.origin_access_identity). The bucket must be "
                "public for CloudFront to read it, letting viewers bypass the "
                "distribution and reach objects directly."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Attach an aws_cloudfront_origin_access_control and set the "
                "origin's origin_access_control_id (or, for legacy setups, set "
                "s3_origin_config.origin_access_identity), then make the bucket "
                "private and grant read access only to CloudFront."
            ),
            tags=frozenset(
                {"cloudfront", "s3", "origin", "public-access", "aws"}
            ),
        )
