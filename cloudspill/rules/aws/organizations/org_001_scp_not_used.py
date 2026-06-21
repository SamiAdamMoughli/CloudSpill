"""ORG-001: Service Control Policies are not enabled for the organization.

Service Control Policies (SCPs) are the organization-wide guardrails that cap
what *any* principal in a member account can do — the only control that a member
account's own admins cannot override. If ``SERVICE_CONTROL_POLICY`` is not in the
organization's ``enabled_policy_types``, that entire layer of defence is off, and
each account is governed only by its own (potentially compromised) IAM.

This rule flags an ``aws_organizations_organization`` (with ALL features) whose
enabled_policy_types does not include SERVICE_CONTROL_POLICY. A
consolidated-billing-only org is reported by ORG-003 instead.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.organizations.org_helpers import enabled_policy_types, governs
from cloudspill.rules.base import register


@register
class OrganizationsScpNotUsed:
    """ORG-001: SERVICE_CONTROL_POLICY not in enabled_policy_types."""

    rule_id = "ORG-001"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_organizations_organization":
            return []
        if not governs(node):
            return []
        if "SERVICE_CONTROL_POLICY" in enabled_policy_types(node):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Service Control Policies are not enabled",
                description=(
                    "enabled_policy_types does not include "
                    "SERVICE_CONTROL_POLICY, so the organization has no SCP "
                    "guardrails. Member accounts are governed only by their own "
                    "IAM, which their admins (or an attacker) can change."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    'Add "SERVICE_CONTROL_POLICY" to enabled_policy_types and '
                    "attach baseline guardrail SCPs to the root / OUs."
                ),
                tags=frozenset(
                    {"organizations", "scp", "guardrails", "governance", "aws"}
                ),
            )
        ]
