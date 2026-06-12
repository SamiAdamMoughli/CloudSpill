"""APIGW-004: API Gateway REST API resource policy grants a wildcard principal.

A resource policy on ``aws_api_gateway_rest_api`` that allows ``Principal: "*"``
(or ``{"AWS": "*"}``) lets any AWS account — and, for edge/regional APIs, any
anonymous caller — invoke the API. This is the resource-policy equivalent of a
fully open endpoint.

The common *safe* pattern is a wildcard principal narrowed by a ``Condition``
(e.g. ``aws:SourceVpce`` for a private API, or ``aws:SourceIp`` for an IP
allowlist). This rule therefore only flags an ``Allow`` statement that combines
a wildcard principal with **no** ``Condition`` to constrain it.

The ``policy`` attribute may be a pre-parsed dict or a JSON string (including a
heredoc), so both shapes are normalized before inspection.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.policy import extract_statements, is_wildcard_principal
from cloudspill.rules.base import register


@register
class APIGatewayResourcePolicyWildcard:
    """APIGW-004: Resource policy allows a wildcard principal without a condition."""

    rule_id = "APIGW-004"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_api_gateway_rest_api":
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
            title="API Gateway resource policy grants a wildcard principal",
            description=(
                "An Allow statement in the resource policy grants Principal '*' "
                "with no Condition to constrain it. Any caller can invoke the API."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Scope the Principal to specific account/role ARNs, or keep the "
                "wildcard but add a Condition such as aws:SourceVpce (private API) "
                "or aws:SourceIp (IP allowlist)."
            ),
            tags=frozenset(
                {"api-gateway", "resource-policy", "public-access", "iam", "aws"}
            ),
        )
