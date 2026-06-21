"""VPC-008: VPC has no S3/DynamoDB gateway endpoint.

A gateway VPC endpoint for S3 (and DynamoDB) keeps traffic to those services on
the AWS private network instead of routing it out through an internet/NAT path.
Beyond cost and reliability, it lets you attach an endpoint policy and keeps the
data plane off the public internet, shrinking the exfiltration surface. A VPC
whose workloads use S3/DynamoDB but has no such endpoint sends that traffic
through its internet egress.

This rule walks the graph for an ``aws_vpc_endpoint`` (service S3 or DynamoDB)
attached to the VPC; finding none, it flags the ``aws_vpc``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class VPCNoS3DdbEndpoint:
    """VPC-008: aws_vpc has no S3/DynamoDB gateway endpoint."""

    rule_id = "VPC-008"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_vpc":
            return []

        if self._has_s3_ddb_endpoint(node, graph):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="VPC has no S3/DynamoDB gateway endpoint",
                description=(
                    "No aws_vpc_endpoint for S3 or DynamoDB references this VPC, so "
                    "traffic to those services leaves through the VPC's internet/NAT "
                    "path instead of the AWS private network — missing endpoint "
                    "policy controls and enlarging the exfiltration surface."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add a gateway aws_vpc_endpoint for com.amazonaws.<region>.s3 "
                    "(and .dynamodb) and associate it with the relevant route "
                    "tables."
                ),
                tags=frozenset(
                    {"vpc", "vpc-endpoint", "data-exfiltration", "private-network", "aws"}
                ),
            )
        ]

    @staticmethod
    def _has_s3_ddb_endpoint(node: IaCNode, graph: ResourceGraph) -> bool:
        for edge in graph.incoming(node.node_id):
            source = graph.get_node(edge.source)
            if source is None or source.resource_type != "aws_vpc_endpoint":
                continue
            service = str(source.attributes.get("service_name", "")).strip().lower()
            if service.endswith(".s3") or service.endswith(".dynamodb"):
                return True
        return False
