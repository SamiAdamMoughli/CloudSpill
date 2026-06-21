"""IAM-013: Role trust policy has a non-restrictive condition.

A trust policy condition is only as good as its values. A condition whose value
is a bare ``"*"`` — common in misconfigured OIDC federation, e.g. a GitHub
Actions ``token.actions.githubusercontent.com:sub`` of ``"repo:*"`` or just
``"*"`` — looks like a guard but constrains nothing, letting any repository (or
any token) assume the role. This is a frequent real-world breach path.

This rule flags an ``aws_iam_role`` whose trust statement has a Condition
containing a wildcard ``*`` value.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.iam.policy_docs import (
    condition_has_wildcard_value,
    trust_statements,
)
from cloudspill.rules.base import register


@register
class IAMOverpermissiveConditionTrust:
    """IAM-013: trust statement Condition contains a wildcard value."""

    rule_id = "IAM-013"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_iam_role":
            return []

        for stmt in trust_statements(node):
            if stmt.get("Effect") != "Allow":
                continue
            if condition_has_wildcard_value(stmt):
                return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Role trust condition is non-restrictive (wildcard value)",
            description=(
                'The role\'s trust policy has a Condition whose value is "*". The '
                "condition appears to constrain who can assume the role but "
                "matches everything — a common OIDC (e.g. GitHub Actions sub) "
                "misconfiguration that lets any token assume the role."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Replace the wildcard condition value with an exact match (e.g. a "
                "specific repo:owner/name:ref for GitHub OIDC) so only the intended "
                "identity can assume the role."
            ),
            tags=frozenset({"iam", "trust-policy", "oidc", "federation", "aws"}),
        )
