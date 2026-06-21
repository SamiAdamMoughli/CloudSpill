"""APIGW-006: API Gateway method does not require an API key.

An ``aws_api_gateway_method`` with ``api_key_required`` unset (it defaults to
``false``) accepts requests with no API key. Without one, the method cannot be
tied to a usage plan, so you lose per-client identification, request-rate and
quota throttling, and usage metering.

This is a defense-in-depth / abuse-control finding, not an authentication
control — API keys are not a substitute for authorization (see APIGW-001).
CORS preflight (``OPTIONS``) methods are exempt: browsers issue them without
credentials, so requiring an API key there would break CORS.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_PREFLIGHT_METHOD = "OPTIONS"


@register
class APIGatewayNoApiKeyRequired:
    """APIGW-006: Method does not require an API key."""

    rule_id = "APIGW-006"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_api_gateway_method":
            return []

        if str(node.attributes.get("http_method", "")).upper() == _PREFLIGHT_METHOD:
            return []  # CORS preflight cannot carry an API key

        if node.attributes.get("api_key_required") is True:
            return []

        http_method = str(node.attributes.get("http_method", "")) or "?"
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title=f"API Gateway method {http_method} does not require an API key",
                description=(
                    "api_key_required is not set on this aws_api_gateway_method, so "
                    "requests are accepted without an API key. The method cannot be "
                    "associated with a usage plan for client identification, "
                    "throttling, or quota enforcement."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set api_key_required = true and attach the API to a usage plan "
                    "(aws_api_gateway_usage_plan) with throttle and quota limits."
                ),
                tags=frozenset(
                    {
                        "api-gateway",
                        "rate-limiting",
                        "usage-plan",
                        "abuse-control",
                        "aws",
                    }
                ),
            )
        ]
