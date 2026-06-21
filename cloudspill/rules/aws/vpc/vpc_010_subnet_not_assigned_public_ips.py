"""VPC-010: Subnet auto-assigns public IPs.

``map_public_ip_on_launch = true`` gives every instance launched into the subnet
a public IP by default, with no explicit opt-in per instance. That quietly turns
the subnet public and exposes workloads directly to the internet — easy to set
once and forget, and a frequent cause of databases and internal services ending
up internet-reachable. Public IP assignment should be a deliberate, per-instance
choice in subnets meant to be public, not a subnet-wide default.

This rule flags an ``aws_subnet`` with ``map_public_ip_on_launch = true``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


def _is_true(value: object) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() == "true"


@register
class VPCSubnetAutoPublicIp:
    """VPC-010: aws_subnet has map_public_ip_on_launch = true."""

    rule_id = "VPC-010"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_subnet":
            return []

        if not _is_true(node.attributes.get("map_public_ip_on_launch")):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Subnet auto-assigns public IPs",
                description=(
                    "map_public_ip_on_launch is true on this aws_subnet, so every "
                    "instance launched into it gets a public IP by default, "
                    "exposing workloads directly to the internet without an "
                    "explicit per-instance choice."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set map_public_ip_on_launch = false; assign public IPs "
                    "deliberately per instance only in subnets intended to be "
                    "public."
                ),
                tags=frozenset(
                    {"vpc", "subnet", "public-ip", "network-exposure", "aws"}
                ),
            )
        ]
