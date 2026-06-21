"""LAMBDA-004: Function is not attached to a VPC.

A function with no ``vpc_config`` runs on Lambda-managed networking with direct
internet egress and cannot reach private resources (RDS, ElastiCache, internal
services) over private networking. For functions that touch internal data, VPC
attachment is what brings them under your network controls — security groups,
NACLs, egress restrictions, and flow-log visibility.

This is a network-segmentation control (LOW); not every function needs a VPC.
The rule flags an ``aws_lambda_function`` with no ``vpc_config`` (or one with no
``subnet_ids``).
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks, as_str_list
from cloudspill.rules.base import register


@register
class LambdaVpcNotConfigured:
    """LAMBDA-004: aws_lambda_function has no vpc_config with subnets."""

    rule_id = "LAMBDA-004"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_lambda_function":
            return []

        for block in as_blocks(node.attributes.get("vpc_config")):
            if as_str_list(block.get("subnet_ids")):
                return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Lambda function is not attached to a VPC",
                description=(
                    "This aws_lambda_function has no vpc_config, so it runs on "
                    "Lambda-managed networking outside your VPC controls and "
                    "cannot reach private resources over private networking."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add a vpc_config with subnet_ids and security_group_ids for "
                    "functions that access internal resources, so they run under "
                    "your network controls."
                ),
                tags=frozenset(
                    {"lambda", "vpc", "network-segmentation", "aws"}
                ),
            )
        ]
