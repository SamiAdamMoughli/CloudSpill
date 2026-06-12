"""CLOUDFRONT-007: Cache behavior does not forward query strings.

In the legacy ``forwarded_values`` configuration, ``query_string = false`` tells
CloudFront to ignore the query string when forwarding to the origin and when
building the cache key. For dynamic content keyed on query parameters
(``?id=``, ``?page=``) that produces incorrect cache hits — one cached response
served for every parameter value.

This is an INFO correctness signal, not a vulnerability. It is reported only for
behaviors still using ``forwarded_values``; behaviors on the modern
``cache_policy_id`` model handle query strings through the cache policy and are
skipped.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register

_BEHAVIOR_KEYS = ("default_cache_behavior", "ordered_cache_behavior")


@register
class CloudFrontQueryStringForwardingDisabled:
    """CLOUDFRONT-007: forwarded_values.query_string is false."""

    rule_id = "CLOUDFRONT-007"
    severity = Severity.INFO

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_cloudfront_distribution":
            return []

        for behavior in self._behaviors(node):
            # Modern cache-policy behaviors don't use forwarded_values.
            if str(behavior.get("cache_policy_id", "")).strip():
                continue
            for fv in as_blocks(behavior.get("forwarded_values")):
                if fv.get("query_string") is False:
                    return [self._finding(node)]
        return []

    @staticmethod
    def _behaviors(node: IaCNode) -> list[dict[str, Any]]:
        """Collect all cache-behavior blocks regardless of how hcl2 shaped them."""
        blocks: list[dict[str, Any]] = []
        for key in _BEHAVIOR_KEYS:
            blocks.extend(as_blocks(node.attributes.get(key)))
        blocks.extend(
            c.attributes for c in node.children if c.resource_type in _BEHAVIOR_KEYS
        )
        return blocks

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="CloudFront cache behavior does not forward query strings",
            description=(
                "A cache behavior sets forwarded_values.query_string = false. "
                "Query parameters are ignored for forwarding and caching, which "
                "can serve stale or incorrect responses for query-keyed content."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Set forwarded_values.query_string = true (forwarding only the "
                "parameters you need), or migrate the behavior to a cache_policy_id "
                "with an appropriate query-string configuration."
            ),
            tags=frozenset(
                {"cloudfront", "caching", "correctness", "aws"}
            ),
        )
