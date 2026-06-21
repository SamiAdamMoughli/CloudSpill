"""IAM-001: Policy grants a wildcard action (Action: "*").

An ``Allow`` statement with ``Action: "*"`` grants every AWS API action. On any
identity it is effectively administrator access; combined with a wildcard
resource it is unrestricted control of the account. It is the single most
common over-privilege finding and the highest-value target for least-privilege
review.

This rule flags an identity policy (``aws_iam_policy`` or an inline
``aws_iam_*_policy``) with an Allow statement whose action list contains ``"*"``.
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


@register
class IAMWildcardAction:
    """IAM-001: identity policy Allow statement grants Action "*"."""

    rule_id = "IAM-001"
    severity = Severity.CRITICAL

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in IDENTITY_POLICY_TYPES:
            return []

        for stmt in identity_statements(node):
            if stmt.get("Effect") != "Allow":
                continue
            if has_wildcard(as_list(stmt.get("Action"))):
                return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="IAM policy grants a wildcard action",
            description=(
                'An Allow statement grants Action "*", permitting every AWS API '
                "call. On any principal this is effectively administrator access."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                'Replace Action "*" with the specific actions the principal '
                "needs (least privilege); scope Resource as well."
            ),
            tags=frozenset(
                {"iam", "wildcard", "over-privilege", "least-privilege", "aws"}
            ),
        )
