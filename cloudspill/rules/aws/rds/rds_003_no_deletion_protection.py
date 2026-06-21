"""RDS-003: Database does not have deletion protection enabled.

``deletion_protection = true`` blocks the API/console from deleting a database
until the flag is turned off, guarding against an accidental ``terraform
destroy``, a fat-fingered console action, or a malicious delete of a stateful,
hard-to-rebuild data store. It is off by default.

This is a resilience control (MEDIUM). The rule flags an ``aws_db_instance`` or
``aws_rds_cluster`` whose ``deletion_protection`` is not true.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_RDS_TYPES = frozenset({"aws_db_instance", "aws_rds_cluster"})


def _is_true(value: object) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() == "true"


@register
class RDSNoDeletionProtection:
    """RDS-003: deletion_protection is not true."""

    rule_id = "RDS-003"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _RDS_TYPES:
            return []

        if _is_true(node.attributes.get("deletion_protection")):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="RDS database has no deletion protection",
                description=(
                    "deletion_protection is not true on this database, so it can "
                    "be deleted through the API or console with no safeguard, "
                    "risking accidental or malicious loss of a stateful data store."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=("Set deletion_protection = true on production databases."),
                tags=frozenset(
                    {"rds", "deletion-protection", "resilience", "database", "aws"}
                ),
            )
        ]
