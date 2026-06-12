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

import json
from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


def _as_statement_list(value: Any) -> list[dict[str, Any]]:
    """Coerce a policy ``Statement`` field to a list of statement dicts."""
    items = value if isinstance(value, list) else [value]
    return [stmt for stmt in items if isinstance(stmt, dict)]


def _extract_statements(node: IaCNode) -> list[dict[str, Any]]:
    """Extract policy statements from the node's ``policy`` attribute.

    Handles a pre-parsed dict, a plain JSON string, and heredoc-wrapped JSON.
    """
    policy_raw = node.attributes.get("policy", "")

    if isinstance(policy_raw, dict):
        return _as_statement_list(policy_raw.get("Statement", []))

    if isinstance(policy_raw, str):
        cleaned = policy_raw.strip()
        # Strip heredoc markers (<<EOF / <<-EOF ... EOF).
        if cleaned.startswith("<<"):
            first_newline = cleaned.index("\n") if "\n" in cleaned else len(cleaned)
            cleaned = cleaned[first_newline + 1 :]
            lines = cleaned.rsplit("\n", 1)
            if len(lines) == 2 and lines[1].strip().isalpha():
                cleaned = lines[0]
            cleaned = cleaned.strip()

        if cleaned.startswith("{"):
            try:
                doc = json.loads(cleaned)
                return _as_statement_list(doc.get("Statement", []))
            except (json.JSONDecodeError, AttributeError):
                return []

    return []


def _is_wildcard_principal(principal: Any) -> bool:
    """True if the Principal field grants access to everyone."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for value in principal.values():
            values = value if isinstance(value, list) else [value]
            if "*" in values:
                return True
    return False


@register
class APIGatewayResourcePolicyWildcard:
    """APIGW-004: Resource policy allows a wildcard principal without a condition."""

    rule_id = "APIGW-004"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_api_gateway_rest_api":
            return []

        for stmt in _extract_statements(node):
            if stmt.get("Effect") != "Allow":
                continue
            if stmt.get("Condition"):
                continue  # a condition constrains the wildcard — common safe pattern
            if _is_wildcard_principal(stmt.get("Principal")):
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
