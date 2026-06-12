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
            return self._check_rest_method(node)
        if node.resource_type == "aws_apigatewayv2_route":
            return self._check_http_route(node)
        return []

    def _check_rest_method(self, node: IaCNode) -> list[Finding]:
        """REST API (v1): ``authorization`` attribute on aws_api_gateway_method."""
        http_method = str(node.attributes.get("http_method", "")).upper()
        if http_method == _PREFLIGHT_METHOD:
            return []  # CORS preflight is unauthenticated by design

        authorization = str(node.attributes.get("authorization", "")).upper()
        if authorization not in _NO_AUTH:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title=f"API Gateway method {http_method or '?'} requires no authorization",
                description=(
                    "authorization is NONE on this aws_api_gateway_method. "
                    "The method is callable by any anonymous client over the internet."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    'Set authorization to "AWS_IAM", "COGNITO_USER_POOLS", or '
                    '"CUSTOM" (with an authorizer_id), or require an API key.'
                ),
                tags=frozenset(
                    {"api-gateway", "authentication", "public-access", "aws"}
                ),
            )
        ]

    def _check_http_route(self, node: IaCNode) -> list[Finding]:
        """HTTP/WebSocket API (v2): ``authorization_type`` on aws_apigatewayv2_route."""
        route_key = str(node.attributes.get("route_key", ""))
        # The $default route and explicit OPTIONS routes are commonly public.
        if route_key.upper().startswith(_PREFLIGHT_METHOD):
            return []

        authorization = str(node.attributes.get("authorization_type", "")).upper()
        if authorization not in _NO_AUTH:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title=f"API Gateway route {route_key or '?'} requires no authorization",
                description=(
                    "authorization_type is NONE on this aws_apigatewayv2_route. "
                    "The route is callable by any anonymous client over the internet."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    'Set authorization_type to "AWS_IAM", "JWT", or "CUSTOM" '
                    "and attach the appropriate authorizer_id."
                ),
                tags=frozenset(
                    {"api-gateway", "authentication", "public-access", "aws"}
                ),
            )
        ]
