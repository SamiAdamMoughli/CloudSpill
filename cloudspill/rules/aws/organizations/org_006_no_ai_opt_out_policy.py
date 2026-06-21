"""ORG-006: AI services opt-out policy is not enabled.

By default several AWS AI services may store and use customer content to improve
their models. An organization-wide AI opt-out policy
(``AISERVICES_OPT_OUT_POLICY``) turns that off for every member account in one
place. Without it, opt-out depends on each account configuring it, and sensitive
content processed by AI services may be retained for model improvement — a data
-governance and privacy/compliance exposure.

This is a data-governance control (LOW). The rule flags an
``aws_organizations_organization`` (with ALL features) whose enabled_policy_types
does not include AISERVICES_OPT_OUT_POLICY.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.organizations.org_helpers import enabled_policy_types, governs
from cloudspill.rules.base import register


@register
class OrganizationsNoAiOptOutPolicy:
    """ORG-006: AISERVICES_OPT_OUT_POLICY not in enabled_policy_types."""

    rule_id = "ORG-006"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_organizations_organization":
            return []
        if not governs(node):
            return []
        if "AISERVICES_OPT_OUT_POLICY" in enabled_policy_types(node):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="AI services opt-out policy is not enabled",
                description=(
                    "enabled_policy_types does not include "
                    "AISERVICES_OPT_OUT_POLICY, so member accounts are not "
                    "centrally opted out of AI-service content use. Sensitive "
                    "content may be retained for model improvement."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    'Add "AISERVICES_OPT_OUT_POLICY" to enabled_policy_types and '
                    "attach an opt-out policy at the root."
                ),
                tags=frozenset(
                    {"organizations", "ai-opt-out", "data-governance", "privacy", "aws"}
                ),
            )
        ]
