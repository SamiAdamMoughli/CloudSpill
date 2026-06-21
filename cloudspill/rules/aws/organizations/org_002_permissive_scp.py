"""ORG-002: Service Control Policy provides no guardrail (allows everything).

An SCP only constrains anything if it withholds permissions — either by Denying
actions or by Allow-listing a narrow set. An SCP whose content is the
``FullAWSAccess`` pattern (an ``Allow`` of ``Action: "*"`` on ``Resource: "*"``)
is a no-op guardrail: it is attached and looks like a control but permits every
action, giving a false sense of governance.

This rule flags an ``aws_organizations_policy`` of type SERVICE_CONTROL_POLICY
whose content contains an Allow-``*``-on-``*`` statement and no Deny statement.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.policy import extract_statements
from cloudspill.rules.base import register


def _has_wildcard(value: Any) -> bool:
    items = value if isinstance(value, list) else [value]
    return any(str(item).strip() == "*" for item in items)


@register
class OrganizationsPermissiveScp:
    """ORG-002: SCP allows * on * with no Deny (no real guardrail)."""

    rule_id = "ORG-002"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_organizations_policy":
            return []
        # type defaults to SERVICE_CONTROL_POLICY when unset.
        policy_type = (
            str(node.attributes.get("type", "SERVICE_CONTROL_POLICY")).strip().upper()
        )
        if policy_type != "SERVICE_CONTROL_POLICY":
            return []

        statements = extract_statements(node.attributes.get("content", ""))
        if not statements:
            return []

        has_deny = any(s.get("Effect") == "Deny" for s in statements)
        allows_all = any(
            s.get("Effect") == "Allow"
            and _has_wildcard(s.get("Action"))
            and _has_wildcard(s.get("Resource"))
            for s in statements
        )
        if has_deny or not allows_all:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Service Control Policy provides no guardrail",
                description=(
                    'This SCP allows Action "*" on Resource "*" and contains no '
                    "Deny, so it permits every action. It is attached like a "
                    "control but enforces nothing — a false sense of governance."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add Deny statements for the actions you want to forbid (e.g. "
                    "leaving the org, disabling CloudTrail/GuardDuty, unapproved "
                    "regions), or replace the wildcard Allow with a narrow allow-list."
                ),
                tags=frozenset(
                    {"organizations", "scp", "guardrails", "governance", "aws"}
                ),
            )
        ]
