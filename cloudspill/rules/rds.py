"""RDS security rules.

| ID      | Finding                          | Severity |
|---------|----------------------------------|----------|
| RDS-001 | publicly_accessible = true       | CRITICAL |
| RDS-002 | Storage encryption not enabled   | HIGH     |
| RDS-003 | Deletion protection not enabled  | MEDIUM   |
| RDS-004 | Automated backups disabled       | LOW      |
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_RDS_TYPES = frozenset({"aws_db_instance", "aws_rds_cluster"})


@register
class RDSPubliclyAccessible:
    """RDS-001: publicly_accessible = true."""

    rule_id = "RDS-001"
    severity = Severity.CRITICAL

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _RDS_TYPES:
            return []
        if node.attributes.get("publicly_accessible") is True:
            return [
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title="Database publicly accessible",
                    description="Database instance is publicly accessible from the internet.",
                    resource=node.node_id,
                    file=node.source_file,
                    line=node.line,
                )
            ]
        return []


@register
class RDSNoEncryption:
    """RDS-002: Storage encryption not enabled."""

    rule_id = "RDS-002"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _RDS_TYPES:
            return []
        if node.attributes.get("storage_encrypted") is not True:
            return [
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title="Storage encryption not enabled",
                    description="Database storage is not encrypted. Data at rest is unprotected.",
                    resource=node.node_id,
                    file=node.source_file,
                    line=node.line,
                )
            ]
        return []


@register
class RDSNoDeletionProtection:
    """RDS-003: Deletion protection not enabled."""

    rule_id = "RDS-003"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _RDS_TYPES:
            return []
        if node.attributes.get("deletion_protection") is not True:
            return [
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title="Deletion protection not enabled",
                    description="Database can be deleted without safeguards. Risk of accidental data loss.",
                    resource=node.node_id,
                    file=node.source_file,
                    line=node.line,
                )
            ]
        return []


@register
class RDSNoBackups:
    """RDS-004: Automated backups disabled."""

    rule_id = "RDS-004"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _RDS_TYPES:
            return []
        retention = node.attributes.get("backup_retention_period", None)
        if retention is not None and retention == 0:
            return [
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title="Automated backups disabled",
                    description="Backup retention period is 0. No automated recovery points are being created.",
                    resource=node.node_id,
                    file=node.source_file,
                    line=node.line,
                )
            ]
        return []
