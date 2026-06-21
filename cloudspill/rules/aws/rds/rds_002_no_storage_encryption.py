"""RDS-002: Database storage is not encrypted at rest.

``storage_encrypted = true`` encrypts the instance/cluster volumes, automated
backups, read replicas, and snapshots with KMS. Without it, the database's data
at rest — and every snapshot derived from it — is stored in plaintext, exposed
to anyone who gains access to the underlying storage or a copied snapshot.
Storage encryption can only be set at creation, so it must be right from the
start.

This rule flags an ``aws_db_instance`` or ``aws_rds_cluster`` whose
``storage_encrypted`` is not true.
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
class RDSNoStorageEncryption:
    """RDS-002: storage_encrypted is not true."""

    rule_id = "RDS-002"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _RDS_TYPES:
            return []

        if _is_true(node.attributes.get("storage_encrypted")):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="RDS storage is not encrypted at rest",
                description=(
                    "storage_encrypted is not true on this database, so its data "
                    "at rest, automated backups, and snapshots are stored in "
                    "plaintext and exposed through any storage or snapshot access."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set storage_encrypted = true (with a kms_key_id for a CMK) at "
                    "creation; existing unencrypted databases must be re-created "
                    "from an encrypted snapshot copy."
                ),
                tags=frozenset(
                    {"rds", "encryption", "data-at-rest", "database", "aws"}
                ),
            )
        ]
