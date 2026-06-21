"""ORG-004: Tag policies are not enabled for the organization.

Tag policies (``TAG_POLICY``) standardize resource tagging across every member
account — enforcing the keys and casing that cost allocation, ownership, and
security automation all depend on. Without them, tagging drifts per account and
the tag-based guardrails and reports built on it become unreliable.

This is a governance control (LOW). The rule flags an
``aws_organizations_organization`` (with ALL features) whose enabled_policy_types
does not include TAG_POLICY.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.organizations.org_helpers import enabled_policy_types, governs
from cloudspill.rules.base import register


@register
class OrganizationsNoTagPolicy:
    """ORG-004: TAG_POLICY not in enabled_policy_types."""

    rule_id = "ORG-004"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_organizations_organization":
            return []
        if not governs(node):
            return []
        if "TAG_POLICY" in enabled_policy_types(node):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Tag policies are not enabled",
                description=(
                    "enabled_policy_types does not include TAG_POLICY, so resource "
                    "tagging is not standardized across accounts. Cost-allocation, "
                    "ownership, and tag-based security automation become "
                    "unreliable."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    'Add "TAG_POLICY" to enabled_policy_types and attach tag '
                    "policies defining required keys and values."
                ),
                tags=frozenset({"organizations", "tag-policy", "governance", "aws"}),
            )
        ]
