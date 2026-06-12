"""CLOUDFRONT-006: CloudFront distribution has no geo restriction.

Geo restriction is set via the nested ``restrictions { geo_restriction { ... } }``
block, whose ``restriction_type`` is one of ``whitelist``, ``blacklist``, or
``none``. A value of ``none`` (or a missing block, which defaults to ``none``)
means the distribution is served to every country.

This is a defense-in-depth / compliance control (LOW): restricting delivery to
the countries you actually serve shrinks the attack surface and helps meet data
residency or sanctions requirements. ``whitelist`` and ``blacklist`` (with a
type set) are treated as clean.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register

_ACTIVE_RESTRICTIONS = frozenset({"whitelist", "blacklist"})


@register
class CloudFrontNoGeoRestriction:
    """CLOUDFRONT-006: geo_restriction is absent or set to 'none'."""

    rule_id = "CLOUDFRONT-006"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_cloudfront_distribution":
            return []

        if self._has_geo_restriction(node):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="CloudFront distribution has no geo restriction",
                description=(
                    "restrictions.geo_restriction is absent or restriction_type is "
                    "'none', so the distribution is served to every country. "
                    "Delivery is not limited to the regions you operate in."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add a restrictions { geo_restriction { restriction_type = "
                    '"whitelist" / "blacklist", locations = [...] } } block scoped '
                    "to the countries you serve."
                ),
                tags=frozenset(
                    {"cloudfront", "geo-restriction", "defense-in-depth", "aws"}
                ),
            )
        ]

    @staticmethod
    def _has_geo_restriction(node: IaCNode) -> bool:
        """True if any geo_restriction sets an active restriction_type."""
        restrictions = as_blocks(node.attributes.get("restrictions"))
        restrictions.extend(
            c.attributes for c in node.children if c.resource_type == "restrictions"
        )

        for block in restrictions:
            for geo in as_blocks(block.get("geo_restriction")):
                rtype = str(geo.get("restriction_type", "")).strip().lower()
                if rtype in _ACTIVE_RESTRICTIONS:
                    return True
        return False
