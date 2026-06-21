"""GD-006: GuardDuty is not auto-enabled for organization members.

In an AWS Organization, ``aws_guardduty_organization_configuration`` controls
whether member accounts get GuardDuty automatically. Without auto-enable, every
newly created or invited account starts with GuardDuty off, leaving blind spots
that persist until someone notices and enables it by hand — exactly the accounts
attackers look for.

Provider versions express this differently:

* newer: ``auto_enable_organization_members`` = ``ALL`` | ``NEW`` | ``NONE``,
* older: ``auto_enable`` (boolean).

This rule flags ``auto_enable_organization_members = "NONE"`` or
``auto_enable = false``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class GuardDutyOrgAutoEnableDisabled:
    """GD-006: org configuration does not auto-enable member accounts."""

    rule_id = "GD-006"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_guardduty_organization_configuration":
            return []

        if not self._auto_enable_off(node):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="GuardDuty is not auto-enabled for organization members",
                description=(
                    "This aws_guardduty_organization_configuration does not "
                    "auto-enable GuardDuty for member accounts. New or invited "
                    "accounts start with threat detection off, creating "
                    "long-lived monitoring blind spots."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    'Set auto_enable_organization_members = "ALL" (or "NEW") so '
                    "member accounts get GuardDuty automatically."
                ),
                tags=frozenset(
                    {"guardduty", "organizations", "auto-enable", "governance", "aws"}
                ),
            )
        ]

    @staticmethod
    def _auto_enable_off(node: IaCNode) -> bool:
        attrs = node.attributes
        members = attrs.get("auto_enable_organization_members")
        if members is not None:
            return str(members).strip().upper() == "NONE"
        if "auto_enable" in attrs:
            value = attrs["auto_enable"]
            if isinstance(value, bool):
                return value is False
            return str(value).strip().lower() == "false"
        return False
