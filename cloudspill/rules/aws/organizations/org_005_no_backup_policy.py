"""ORG-005: Backup policies are not enabled for the organization.

Backup policies (``BACKUP_POLICY``) push a central AWS Backup configuration —
schedules, retention, vaults — to every member account, so resilience does not
depend on each team remembering to set it up. Without them, backup coverage is
inconsistent across accounts and some workloads have no managed restore point at
all, the gap ransomware and accidental-deletion incidents exploit.

This is a resilience / governance control (LOW). The rule flags an
``aws_organizations_organization`` (with ALL features) whose enabled_policy_types
does not include BACKUP_POLICY.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.organizations.org_helpers import enabled_policy_types, governs
from cloudspill.rules.base import register


@register
class OrganizationsNoBackupPolicy:
    """ORG-005: BACKUP_POLICY not in enabled_policy_types."""

    rule_id = "ORG-005"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_organizations_organization":
            return []
        if not governs(node):
            return []
        if "BACKUP_POLICY" in enabled_policy_types(node):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Backup policies are not enabled",
                description=(
                    "enabled_policy_types does not include BACKUP_POLICY, so AWS "
                    "Backup is not centrally enforced across accounts. Backup "
                    "coverage is inconsistent and some workloads may have no "
                    "managed restore point."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    'Add "BACKUP_POLICY" to enabled_policy_types and attach backup '
                    "policies defining schedules, retention, and vaults."
                ),
                tags=frozenset(
                    {
                        "organizations",
                        "backup-policy",
                        "resilience",
                        "governance",
                        "aws",
                    }
                ),
            )
        ]
