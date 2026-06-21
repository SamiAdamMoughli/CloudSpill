"""VPC-001: The default VPC is being managed/used.

The default VPC ships with a public subnet in every AZ, an attached internet
gateway, a main route table that reaches it, and a wide-open default security
group. Declaring ``aws_default_vpc`` adopts that permissive, internet-reachable
network as real infrastructure instead of building a purpose-designed VPC with
intentional segmentation.

This is a network-hygiene control (LOW). The rule flags the presence of an
``aws_default_vpc`` resource.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class VPCDefaultVpcInUse:
    """VPC-001: aws_default_vpc resource is declared."""

    rule_id = "VPC-001"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_default_vpc":
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="The default VPC is being used",
                description=(
                    "An aws_default_vpc is declared, adopting the account's default "
                    "VPC — with its public subnets, internet gateway, and wide-open "
                    "default security group — as real infrastructure instead of a "
                    "purpose-designed, segmented network."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Build a dedicated VPC with intentional subnets, routing, and "
                    "security groups; avoid placing workloads in the default VPC."
                ),
                tags=frozenset({"vpc", "default-vpc", "network-segmentation", "aws"}),
            )
        ]
