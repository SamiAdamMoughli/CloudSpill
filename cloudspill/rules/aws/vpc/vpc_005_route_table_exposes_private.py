"""VPC-005: The default route table is used for custom routing.

Every VPC has a main/default route table that subnets fall into implicitly when
not explicitly associated with another. Adding routes to
``aws_default_route_table`` means any subnet that was *not* deliberately
associated elsewhere silently inherits those routes — so a forgotten subnet can
pick up an internet or peering route without anyone intending it. Best practice
is to leave the default route table minimal and route through explicit,
purpose-built route tables.

This rule flags an ``aws_default_route_table`` that defines routes.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.vpc.routes import routes
from cloudspill.rules.base import register


@register
class VPCDefaultRouteTableUsed:
    """VPC-005: aws_default_route_table defines routes."""

    rule_id = "VPC-005"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_default_route_table":
            return []

        if not routes(node):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Default route table is used for custom routing",
                description=(
                    "This aws_default_route_table defines routes. Subnets not "
                    "explicitly associated with another route table inherit these "
                    "routes implicitly, so a forgotten subnet can silently pick up "
                    "internet or peering connectivity."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Keep the default route table minimal and route subnets "
                    "through explicit aws_route_table resources with intentional "
                    "associations."
                ),
                tags=frozenset(
                    {"vpc", "routing", "default-route-table", "network-segmentation", "aws"}
                ),
            )
        ]
