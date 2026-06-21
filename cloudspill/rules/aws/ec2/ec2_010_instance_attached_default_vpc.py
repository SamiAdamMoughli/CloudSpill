"""EC2-010: Instance is launched into the default VPC or a default subnet.

The default VPC ships with a permissive setup — an internet gateway, a main
route table that reaches it, and a default security group — none of which was
designed around your workload. Running real workloads there inherits that loose
posture instead of an intentionally segmented network.

This rule flags an ``aws_instance`` that references a default network resource
(``aws_default_vpc`` or ``aws_default_subnet``) through the resource graph,
e.g. via ``subnet_id`` or ``vpc_security_group_ids``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_DEFAULT_NETWORK_TYPES = frozenset({"aws_default_vpc", "aws_default_subnet"})


@register
class EC2InstanceInDefaultVpc:
    """EC2-010: aws_instance attached to a default VPC/subnet."""

    rule_id = "EC2-010"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_instance":
            return []

        if not self._uses_default_network(node, graph):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Instance is launched into the default VPC or subnet",
                description=(
                    "This aws_instance references an aws_default_vpc or "
                    "aws_default_subnet. The default network has a permissive, "
                    "internet-reachable layout that was not designed for this "
                    "workload."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Launch the instance into a purpose-built VPC and subnet with "
                    "intentional routing and security groups instead of the "
                    "account's default network."
                ),
                tags=frozenset(
                    {"ec2", "vpc", "network-segmentation", "default-vpc", "aws"}
                ),
            )
        ]

    @staticmethod
    def _uses_default_network(node: IaCNode, graph: ResourceGraph) -> bool:
        for edge in graph.outgoing(node.node_id):
            target = graph.get_node(edge.target)
            if target is not None and target.resource_type in _DEFAULT_NETWORK_TYPES:
                return True
        return False
