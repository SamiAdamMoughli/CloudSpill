"""VPC-004: Route table sends a default route to an internet gateway.

A ``0.0.0.0/0`` route pointing at an internet gateway makes every subnet
associated with that route table *public* — instances there can be reached from,
and reach, the open internet directly. That is correct for a deliberate public
subnet, but applied to a route table used by application or data subnets it
exposes workloads that should be private and egress-only through a NAT.

This rule flags a default route (``0.0.0.0/0``) whose target is an internet
gateway, on an ``aws_route`` resource or an inline ``aws_route_table`` route.
Confirm the associated subnets are intended to be public.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.vpc.routes import (
    is_default_route,
    routes,
    targets_internet_gateway,
)
from cloudspill.rules.base import register


@register
class VPCInternetGatewayRoute:
    """VPC-004: default route targets an internet gateway."""

    rule_id = "VPC-004"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        for route in routes(node):
            if is_default_route(route) and targets_internet_gateway(route):
                return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Route table sends a default route to an internet gateway",
            description=(
                "A 0.0.0.0/0 route targets an internet gateway, making every "
                "subnet using this route table public. Workloads that should be "
                "private are exposed to and from the open internet."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Use an internet-gateway default route only for deliberate public "
                "subnets; route private subnets' egress through a NAT gateway "
                "instead."
            ),
            tags=frozenset(
                {"vpc", "routing", "internet-gateway", "network-exposure", "aws"}
            ),
        )
