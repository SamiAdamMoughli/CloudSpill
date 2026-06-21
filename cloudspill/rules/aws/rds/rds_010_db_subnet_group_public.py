"""RDS-010: DB subnet group spans a public subnet.

A DB subnet group lists the subnets a database can be placed in. If any of those
is a public subnet (``map_public_ip_on_launch = true``), the database can land in
a subnet with a direct route to the internet — undermining the private-tier
placement a database should have, and a prerequisite for accidental public
exposure. Database subnet groups should contain only private subnets.

This rule walks the graph from ``aws_db_subnet_group`` to its referenced
``aws_subnet`` resources and flags the group if any subnet auto-assigns public
IPs.
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
class RDSDbSubnetGroupPublic:
    """RDS-010: aws_db_subnet_group references a public subnet."""

    rule_id = "RDS-010"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_db_subnet_group":
            return []

        if not self._spans_public_subnet(node, graph):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="DB subnet group spans a public subnet",
                description=(
                    "This aws_db_subnet_group references a subnet with "
                    "map_public_ip_on_launch = true. A database placed there can "
                    "sit in a subnet with a direct internet route, undermining "
                    "private-tier placement."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Build the DB subnet group from private subnets only (no "
                    "map_public_ip_on_launch, no internet-gateway route)."
                ),
                tags=frozenset(
                    {"rds", "subnet-group", "network-exposure", "database", "aws"}
                ),
            )
        ]

    @staticmethod
    def _spans_public_subnet(node: IaCNode, graph: ResourceGraph) -> bool:
        for edge in graph.outgoing(node.node_id):
            target = graph.get_node(edge.target)
            if (
                target is not None
                and target.resource_type == "aws_subnet"
                and _is_true(target.attributes.get("map_public_ip_on_launch"))
            ):
                return True
        return False
