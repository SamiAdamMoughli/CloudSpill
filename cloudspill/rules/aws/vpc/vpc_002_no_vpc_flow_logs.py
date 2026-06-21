"""VPC-002: VPC has no flow logs.

VPC flow logs record accepted and rejected IP traffic across the VPC's network
interfaces — the primary data source for detecting exfiltration, lateral
movement, port scans, and connections to known-bad hosts, and for reconstructing
network activity during an incident. Without them, the VPC's network layer is a
blind spot.

This rule walks the graph for an ``aws_flow_log`` that references the VPC;
finding none, it flags the ``aws_vpc``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class VPCNoFlowLogs:
    """VPC-002: aws_vpc has no associated aws_flow_log."""

    rule_id = "VPC-002"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_vpc":
            return []

        if self._has_flow_log(node, graph):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="VPC has no flow logs",
                description=(
                    "No aws_flow_log references this aws_vpc, so there is no record "
                    "of accepted/rejected network traffic. Exfiltration, lateral "
                    "movement, and scanning go unobserved at the network layer."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add an aws_flow_log for the VPC (to CloudWatch Logs or S3) "
                    "capturing ALL traffic."
                ),
                tags=frozenset(
                    {"vpc", "flow-logs", "network-monitoring", "detection", "aws"}
                ),
            )
        ]

    @staticmethod
    def _has_flow_log(node: IaCNode, graph: ResourceGraph) -> bool:
        for edge in graph.incoming(node.node_id):
            source = graph.get_node(edge.source)
            if source is not None and source.resource_type == "aws_flow_log":
                return True
        return False
