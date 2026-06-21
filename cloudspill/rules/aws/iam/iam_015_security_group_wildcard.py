"""IAM-015: Policy grants account-wide security-group modification.

A statement that allows the security-group write actions (e.g.
``ec2:AuthorizeSecurityGroupIngress``, ``ec2:RevokeSecurityGroupEgress``, or a
broad ``ec2:*``) on ``Resource: "*"`` lets the principal open ingress on *any*
security group in the account. That is a direct network-exposure escalation: a
compromised principal can punch ``0.0.0.0/0`` holes to reach internal services,
independent of who owns the group.

This rule flags an identity policy whose Allow statement grants a
security-group-modifying EC2 action on a wildcard resource.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.iam.policy_docs import (
    IDENTITY_POLICY_TYPES,
    as_list,
    has_wildcard,
    identity_statements,
)
from cloudspill.rules.base import register

_SG_ACTION_HINTS = (
    "authorizesecuritygroup",
    "revokesecuritygroup",
    "modifysecuritygroup",
    "createsecuritygroup",
    "deletesecuritygroup",
)


def _grants_sg_modify(action: str) -> bool:
    lowered = action.strip().lower()
    if lowered in ("*", "ec2:*"):
        return True
    return any(hint in lowered for hint in _SG_ACTION_HINTS)


@register
class IAMSecurityGroupWildcard:
    """IAM-015: policy allows security-group modification on Resource "*"."""

    rule_id = "IAM-015"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in IDENTITY_POLICY_TYPES:
            return []

        for stmt in identity_statements(node):
            if stmt.get("Effect") != "Allow":
                continue
            if not has_wildcard(as_list(stmt.get("Resource"))):
                continue
            actions = [str(a) for a in as_list(stmt.get("Action"))]
            if any(_grants_sg_modify(a) for a in actions):
                return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="IAM policy allows account-wide security-group modification",
            description=(
                "An Allow statement grants security-group-modifying EC2 actions on "
                'Resource "*". The principal can open ingress on any security '
                "group in the account, reaching internal services regardless of "
                "ownership."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Scope security-group actions to specific group ARNs, and add "
                "conditions (e.g. ec2:Vpc) to limit which groups can be changed."
            ),
            tags=frozenset({"iam", "ec2", "security-group", "network-exposure", "aws"}),
        )
