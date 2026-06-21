"""ORG-003: Organization uses consolidated-billing features only.

``aws_organizations_organization`` has two feature sets. ``ALL`` unlocks the
governance controls — SCPs, tag policies, backup policies, delegated
administration. ``CONSOLIDATED_BILLING`` gives you only a shared bill: no SCPs,
no policy types, no central guardrails of any kind. An org stuck on
consolidated billing cannot enforce anything across its accounts.

This rule flags an ``aws_organizations_organization`` whose ``feature_set`` is
``CONSOLIDATED_BILLING``. (It is the single root-cause finding for that case;
the policy-type rules stay quiet so as not to pile on.)
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.organizations.org_helpers import feature_set
from cloudspill.rules.base import register


@register
class OrganizationsConsolidatedBillingOnly:
    """ORG-003: feature_set is CONSOLIDATED_BILLING."""

    rule_id = "ORG-003"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_organizations_organization":
            return []
        if feature_set(node) != "CONSOLIDATED_BILLING":
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Organization uses consolidated-billing features only",
                description=(
                    "feature_set is CONSOLIDATED_BILLING, so the organization "
                    "cannot use SCPs, tag/backup policies, or any central "
                    "governance control. Nothing can be enforced across member "
                    "accounts."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    'Set feature_set = "ALL" to enable organization-wide '
                    "governance, then turn on SCPs and the policy types you need."
                ),
                tags=frozenset({"organizations", "feature-set", "governance", "aws"}),
            )
        ]
