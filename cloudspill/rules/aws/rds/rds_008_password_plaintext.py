"""RDS-008: Master password is set as a literal value.

Setting ``password`` (instance) or ``master_password`` (cluster) to a literal
string bakes the database credential into the Terraform configuration and, worse,
into the state file in plaintext — readable by anyone with state access and
trivially leaked through a committed repo or CI artifact. RDS can instead manage
the master password in Secrets Manager (``manage_master_user_password = true``).

This rule flags an ``aws_db_instance`` / ``aws_rds_cluster`` whose password is a
non-empty literal and that does not delegate to managed master passwords. A value
that is still an unresolved interpolation (``${...}``) is skipped, since its real
content is not knowable statically.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_RDS_TYPES = frozenset({"aws_db_instance", "aws_rds_cluster"})
_PASSWORD_KEYS = ("password", "master_password")


def _is_true(value: object) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() == "true"


def _is_literal_secret(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if not stripped or "${" in stripped:
        return False  # empty or unresolved interpolation
    return True


@register
class RDSPasswordPlaintext:
    """RDS-008: master password set as a literal value."""

    rule_id = "RDS-008"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _RDS_TYPES:
            return []
        if _is_true(node.attributes.get("manage_master_user_password")):
            return []

        if not any(
            _is_literal_secret(node.attributes.get(key)) for key in _PASSWORD_KEYS
        ):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="RDS master password is set as a literal value",
                description=(
                    "A literal master password is set on this database, so the "
                    "credential is stored in the Terraform configuration and in "
                    "state in plaintext, readable by anyone with access to either."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set manage_master_user_password = true to have RDS manage the "
                    "credential in Secrets Manager, or source it from a secret "
                    "rather than a literal."
                ),
                tags=frozenset(
                    {"rds", "plaintext-credentials", "secrets", "database", "aws"}
                ),
            )
        ]
