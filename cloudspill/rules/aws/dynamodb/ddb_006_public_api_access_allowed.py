"""DDB-006: DynamoDB resource policy grants public API access.

DynamoDB supports resource-based policies through ``aws_dynamodb_resource_policy``
(attached to a table or stream). An ``Allow`` statement whose ``Principal`` is a
wildcard (``"*"`` or ``{"AWS": "*"}``) with no ``Condition`` to constrain it
exposes the table's data-plane API — GetItem, Query, Scan, PutItem — to every
AWS principal, which is effectively public access to the data.

As with API Gateway resource policies, a wildcard principal narrowed by a
``Condition`` (e.g. ``aws:PrincipalOrgID`` or ``aws:SourceVpce``) is a common
safe pattern, so this rule only flags an ``Allow`` + wildcard principal +
**no** Condition. The ``policy`` attribute may be a dict or a JSON string
(including a heredoc), normalized by the shared policy helpers.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.policy import extract_statements, is_wildcard_principal
from cloudspill.rules.base import register


@register
class DynamoDBPublicApiAccess:
    """DDB-006: aws_dynamodb_resource_policy allows a wildcard principal."""

    rule_id = "DDB-006"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_dynamodb_resource_policy":
            return []

        for stmt in extract_statements(node.attributes.get("policy", "")):
            if stmt.get("Effect") != "Allow":
                continue
            if stmt.get("Condition"):
                continue  # a condition constrains the wildcard — common safe pattern
            if is_wildcard_principal(stmt.get("Principal")):
                return [self._finding(node)]

        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="DynamoDB resource policy grants public API access",
            description=(
                "An Allow statement in this aws_dynamodb_resource_policy grants "
                "Principal '*' with no Condition. Any AWS principal can call the "
                "table's data-plane API (GetItem, Query, Scan, PutItem)."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Scope the Principal to specific account/role ARNs, or keep the "
                "wildcard but add a Condition such as aws:PrincipalOrgID or "
                "aws:SourceVpce to constrain who can call the table."
            ),
            tags=frozenset(
                {"dynamodb", "resource-policy", "public-access", "iam", "aws"}
            ),
        )
