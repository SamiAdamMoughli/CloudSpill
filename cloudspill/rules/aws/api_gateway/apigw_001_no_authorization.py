"""APIGW-001: API Gateway method or route enforces no authorization.

An API Gateway method (REST / v1) or route (HTTP & WebSocket / v2) with
authorization set to ``NONE`` is reachable by any anonymous caller. This is
the API-layer equivalent of an open security group: the endpoint is exposed
to the entire internet with no identity check.

REST API methods carry an ``authorization`` attribute; v2 routes carry
``authorization_type``. CORS preflight (``OPTIONS``) methods are exempt —
they must be callable without credentials for browsers to function, so an
``OPTIONS`` method with no authorization is expected, not a finding.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

# Values that mean "no caller identity is required".
_NO_AUTH = frozenset({"NONE", ""})

# CORS preflight requests are unauthenticated by design.
_PREFLIGHT_METHOD = "OPTIONS"


@register
class APIGatewayNoAuthorization:
    """APIGW-001: Method/route has no authorization configured."""

    rule_id = "APIGW-001"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type == "aws_api_gateway_method":
            if not self._is_rest_method_open(node):
                return []
            target = str(node.attributes.get("http_method", "")) or "?"
            return [self._finding(node, kind="method", target=target)]

        if node.resource_type == "aws_apigatewayv2_route":
            if not self._is_http_route_open(node):
                return []
            target = str(node.attributes.get("route_key", "")) or "?"
            return [self._finding(node, kind="route", target=target)]

        return []

    @staticmethod
    def _is_rest_method_open(node: IaCNode) -> bool:
        """REST API (v1): authorization is NONE and not a CORS preflight method."""
        if str(node.attributes.get("http_method", "")).upper() == _PREFLIGHT_METHOD:
            return False  # CORS preflight is unauthenticated by design
        return str(node.attributes.get("authorization", "")).upper() in _NO_AUTH

    @staticmethod
    def _is_http_route_open(node: IaCNode) -> bool:
        """HTTP/WebSocket API (v2): authorization_type is NONE, not an OPTIONS route."""
        route_key = str(node.attributes.get("route_key", ""))
        if route_key.upper().startswith(_PREFLIGHT_METHOD):
            return False
        return str(node.attributes.get("authorization_type", "")).upper() in _NO_AUTH

    def _finding(self, node: IaCNode, kind: str, target: str) -> Finding:
        """Build the finding for an unauthenticated method (v1) or route (v2)."""
        if kind == "method":
            attr, resource_type = "authorization", "aws_api_gateway_method"
            remediation = (
                'Set authorization to "AWS_IAM", "COGNITO_USER_POOLS", or '
                '"CUSTOM" (with an authorizer_id), or require an API key.'
            )
        else:
            attr, resource_type = "authorization_type", "aws_apigatewayv2_route"
            remediation = (
                'Set authorization_type to "AWS_IAM", "JWT", or "CUSTOM" '
                "and attach the appropriate authorizer_id."
            )

        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title=f"API Gateway {kind} {target} requires no authorization",
            description=(
                f"{attr} is NONE on this {resource_type}. "
                f"The {kind} is callable by any anonymous client over the internet."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=remediation,
            tags=frozenset({"api-gateway", "authentication", "public-access", "aws"}),
        )
