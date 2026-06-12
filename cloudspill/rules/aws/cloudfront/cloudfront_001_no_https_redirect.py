"""CLOUDFRONT-001: CloudFront distribution serves viewers over plain HTTP.

Each cache behavior on an ``aws_cloudfront_distribution`` carries a
``viewer_protocol_policy``:

* ``allow-all``        — HTTP and HTTPS both served (insecure)
* ``redirect-to-https``— HTTP is 301-redirected to HTTPS (recommended)
* ``https-only``       — HTTP is rejected (recommended)

A policy of ``allow-all`` on any behavior lets viewers exchange data over
unencrypted HTTP, exposing it to interception and tampering. This rule flags a
distribution if its ``default_cache_behavior`` or any ``ordered_cache_behavior``
uses ``allow-all``.

python-hcl2 may surface a behavior block as a dict, a single-element list of
dicts, or — for inline blocks — as a child node, so all three shapes are
checked.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

# Policies that prevent plain-HTTP delivery. Anything else present (notably
# "allow-all", but also an unknown/typo value) is treated as insecure.
_SECURE_POLICIES = frozenset({"redirect-to-https", "https-only"})
_BEHAVIOR_KEYS = ("default_cache_behavior", "ordered_cache_behavior")


@register
class CloudFrontNoHttpsRedirect:
    """CLOUDFRONT-001: A cache behavior allows plain HTTP (viewer_protocol_policy)."""

    rule_id = "CLOUDFRONT-001"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_cloudfront_distribution":
            return []

        for behavior in self._behaviors(node):
            policy = str(behavior.get("viewer_protocol_policy", "")).strip().lower()
            # Only judge behaviors that actually declare a policy; a missing
            # value is left to other tooling rather than flagged as insecure.
            if policy and policy not in _SECURE_POLICIES:
                return [self._finding(node)]
        return []

    @staticmethod
    def _behaviors(node: IaCNode) -> list[dict[str, Any]]:
        """Collect all cache-behavior blocks regardless of how hcl2 shaped them."""
        blocks: list[dict[str, Any]] = []
        for key in _BEHAVIOR_KEYS:
            value = node.attributes.get(key)
            if isinstance(value, list):
                blocks.extend(b for b in value if isinstance(b, dict))
            elif isinstance(value, dict):
                blocks.append(value)
        blocks.extend(
            c.attributes for c in node.children if c.resource_type in _BEHAVIOR_KEYS
        )
        return blocks

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="CloudFront distribution allows plain HTTP",
            description=(
                "A cache behavior sets viewer_protocol_policy = 'allow-all', so "
                "viewers can connect over unencrypted HTTP. Traffic is exposed to "
                "interception and tampering."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Set viewer_protocol_policy to 'redirect-to-https' or 'https-only' "
                "on every default and ordered cache behavior."
            ),
            tags=frozenset(
                {"cloudfront", "encryption-in-transit", "tls", "public-access", "aws"}
            ),
        )
