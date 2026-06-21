"""EC2-004: Instance is assigned a public IP address.

``associate_public_ip_address = true`` gives the instance a routable public IP,
putting it directly on the internet rather than behind a NAT gateway or load
balancer. That widens the attack surface to every internet host and is rarely
necessary for application or backend instances.

This rule flags an ``aws_instance`` (or its ``network_interface`` block) that
explicitly associates a public IP.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register


def _is_true(value: object) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() == "true"


@register
class EC2PublicIP:
    """EC2-004: aws_instance associates a public IP address."""

    rule_id = "EC2-004"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_instance":
            return []

        if not self._has_public_ip(node):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Instance is assigned a public IP address",
                description=(
                    "associate_public_ip_address is true on this aws_instance, so "
                    "it is reachable directly from the internet rather than via a "
                    "NAT gateway or load balancer, widening its attack surface."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set associate_public_ip_address = false and place the "
                    "instance in a private subnet, exposing it through a load "
                    "balancer or NAT only if it must reach the internet."
                ),
                tags=frozenset(
                    {"ec2", "public-ip", "network-exposure", "aws"}
                ),
            )
        ]

    @staticmethod
    def _has_public_ip(node: IaCNode) -> bool:
        if _is_true(node.attributes.get("associate_public_ip_address")):
            return True
        for block in as_blocks(node.attributes.get("network_interface")):
            if _is_true(block.get("associate_public_ip_address")):
                return True
        return False
