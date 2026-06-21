"""VPC-007: Elastic IP attached directly to an instance (no NAT gateway).

Associating an Elastic IP straight to an instance (the ``instance`` argument on
``aws_eip``) gives that host a permanent public address and inbound reachability,
rather than keeping it private and routing outbound traffic through a shared NAT
gateway. It is a common sign that NAT egress was skipped: each instance is
individually exposed instead of sitting behind one controlled egress point.

This rule flags an ``aws_eip`` associated directly with an instance.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class VPCNatGatewayNotUsed:
    """VPC-007: aws_eip is associated directly to an instance."""

    rule_id = "VPC-007"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_eip":
            return []

        if not str(node.attributes.get("instance", "")).strip():
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Elastic IP attached directly to an instance",
                description=(
                    "This aws_eip is associated directly with an instance, giving "
                    "the host a permanent public address and inbound reachability "
                    "instead of keeping it private with shared NAT-gateway egress."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Place instances in private subnets and route outbound traffic "
                    "through a NAT gateway; expose services through a load balancer "
                    "rather than per-instance Elastic IPs."
                ),
                tags=frozenset(
                    {"vpc", "nat-gateway", "elastic-ip", "network-exposure", "aws"}
                ),
            )
        ]
