"""VPC-006: Route sends a broad CIDR over a VPC peering connection.

A route to a ``vpc_peering_connection_id`` with an overly broad destination —
``0.0.0.0/0`` or an entire RFC 1918 range like ``10.0.0.0/8`` — sends far more
traffic across the peering link than the specific subnets that need to
communicate. That widens the trust between the two VPCs: a compromise on one side
gains a route into broad swaths of the other, undermining the segmentation
peering is supposed to keep narrow.

This rule flags a route whose target is a VPC peering connection and whose
destination is ``0.0.0.0/0`` or a ``/8`` (or broader) private supernet.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.vpc.routes import destination, routes
from cloudspill.rules.base import register

_BROAD_CIDRS = frozenset({"0.0.0.0/0", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"})


def _targets_peering(route: dict[str, Any]) -> bool:
    return bool(str(route.get("vpc_peering_connection_id", "")).strip())


def _is_broad(cidr: str) -> bool:
    if cidr in _BROAD_CIDRS:
        return True
    # Any prefix length <= /8 is a very broad supernet.
    if "/" in cidr:
        try:
            return int(cidr.split("/", 1)[1]) <= 8
        except ValueError:
            return False
    return False


@register
class VPCPeeringUnrestrictedCidr:
    """VPC-006: peering route uses a broad destination CIDR."""

    rule_id = "VPC-006"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        for route in routes(node):
            if _targets_peering(route) and _is_broad(destination(route)):
                return [self._finding(node, destination(route))]
        return []

    def _finding(self, node: IaCNode, cidr: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Route sends a broad CIDR over a VPC peering connection",
            description=(
                f"A route sends {cidr} across a VPC peering connection — far "
                "broader than the subnets that need to communicate. A compromise "
                "on one side gains a route into broad swaths of the peer VPC."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Route only the specific subnet CIDRs that must reach the peer "
                "over the peering connection, not 0.0.0.0/0 or whole RFC 1918 "
                "ranges."
            ),
            tags=frozenset(
                {"vpc", "peering", "routing", "network-segmentation", "aws"}
            ),
        )
