"""RDS-001: Database instance is publicly accessible.

``publicly_accessible = true`` gives an RDS instance a public endpoint, putting
the database directly on the internet where it is exposed to scanning,
brute-force, and exploitation of any auth or engine vulnerability. A database
should sit in a private subnet, reachable only from the application tier.

This rule flags an ``aws_db_instance`` with ``publicly_accessible`` set true.
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
class RDSPubliclyAccessible:
    """RDS-001: aws_db_instance has publicly_accessible = true."""

    rule_id = "RDS-001"
    severity = Severity.CRITICAL

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_db_instance":
            return []

        if not _is_true(node.attributes.get("publicly_accessible")):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="RDS instance is publicly accessible",
                description=(
                    "publicly_accessible is true on this aws_db_instance, giving "
                    "it a public endpoint exposed to internet scanning, "
                    "brute-force, and engine exploits."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set publicly_accessible = false and place the instance in a "
                    "private subnet reachable only from the application tier."
                ),
                tags=frozenset(
                    {"rds", "public-access", "network-exposure", "database", "aws"}
                ),
            )
        ]
