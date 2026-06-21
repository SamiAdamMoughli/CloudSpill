"""CLOUDFRONT-008: Cache key omits the Host header.

In the legacy ``forwarded_values`` model, the cache key is built from the
headers listed in ``forwarded_values.headers``. When a behavior serves a
host-sensitive custom origin (e.g. one backend answering for several domains)
and ``Host`` is not in that list, responses for different hosts collapse to the
same cache key — the classic setup for cross-host cache poisoning or simply
serving the wrong site's content.

This is an INFO awareness signal, reported only for behaviors that:

* still use ``forwarded_values`` (modern ``cache_policy_id`` behaviors are
  skipped — the cache policy governs the key there), and
* forward at least one header (``headers`` is non-empty) but not ``Host``.

A behavior forwarding no headers at all is normal for cacheable static content
and is not flagged, and ``headers = ["*"]`` (all headers) includes ``Host`` and
is clean. Note that pure S3 origins legitimately omit ``Host``; this is why the
finding is INFO rather than a higher severity.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks, as_str_list
from cloudspill.rules.base import register

_BEHAVIOR_KEYS = ("default_cache_behavior", "ordered_cache_behavior")


@register
class CloudFrontCacheKeyMissingHostHeader:
    """CLOUDFRONT-008: forwarded_values.headers forwards headers but not Host."""

    rule_id = "CLOUDFRONT-008"
    severity = Severity.INFO

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_cloudfront_distribution":
            return []

        for behavior in self._behaviors(node):
            if str(behavior.get("cache_policy_id", "")).strip():
                continue  # modern cache policy governs the cache key
            for fv in as_blocks(behavior.get("forwarded_values")):
                headers = [h.strip().lower() for h in as_str_list(fv.get("headers"))]
                if not headers:
                    continue  # forwards no headers — normal for static content
                if "*" in headers or "host" in headers:
                    continue
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
            title="CloudFront cache key omits the Host header",
            description=(
                "A cache behavior forwards headers via forwarded_values but does "
                "not include 'Host'. For a host-sensitive origin, responses for "
                "different hosts share one cache key, enabling cross-host cache "
                "poisoning or wrong-content delivery."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Add 'Host' to forwarded_values.headers for host-sensitive custom "
                "origins, or migrate the behavior to a cache_policy_id whose cache "
                "key includes the Host header."
            ),
            tags=frozenset({"cloudfront", "caching", "cache-poisoning", "aws"}),
        )
