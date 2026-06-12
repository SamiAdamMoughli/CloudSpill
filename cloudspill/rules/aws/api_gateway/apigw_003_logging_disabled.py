"""APIGW-003: API Gateway stage has access logging disabled.

An API Gateway stage should emit access logs to CloudWatch. Without them you
lose the per-request audit trail (caller IP, latency, status, integration
errors) needed to investigate abuse, debug 4xx/5xx spikes, and satisfy
compliance logging requirements.

How access logging is configured in Terraform
---------------------------------------------
Both REST stages (``aws_api_gateway_stage``) and HTTP/WebSocket stages
(``aws_apigatewayv2_stage``) enable it through an ``access_log_settings``
block that must carry a ``destination_arn`` (the CloudWatch log group):

    resource "aws_api_gateway_stage" "prod" {
      access_log_settings {
        destination_arn = aws_cloudwatch_log_group.api.arn
        format          = "$context.requestId ..."
      }
    }

python-hcl2 may surface that block as a dict, a single-element list of dicts,
or — for inline blocks — as a child node, so all three shapes are checked. A
block with no ``destination_arn`` counts as logging disabled.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_STAGE_TYPES = frozenset({"aws_api_gateway_stage", "aws_apigatewayv2_stage"})


@register
class APIGatewayLoggingDisabled:
    """APIGW-003: Stage has no access logging configured."""

    rule_id = "APIGW-003"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _STAGE_TYPES:
            return []

        if self._has_access_logging(node):
            return []

        stage_name = str(
            node.attributes.get("stage_name", "")
            or node.attributes.get("name", "")
        )
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title=f"API Gateway stage '{stage_name or '?'}' has access logging disabled",
                description=(
                    "No access_log_settings block with a destination_arn is "
                    "configured on this stage. Per-request access logs are not "
                    "delivered to CloudWatch, leaving no audit trail."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add an access_log_settings block with destination_arn set "
                    "to a CloudWatch log group ARN and a log format string."
                ),
                tags=frozenset(
                    {"api-gateway", "logging", "audit", "observability", "aws"}
                ),
            )
        ]

    @staticmethod
    def _has_access_logging(node: IaCNode) -> bool:
        """True if the stage has an access_log_settings block with a destination."""
        settings = node.attributes.get("access_log_settings", None)

        blocks: list[Any] = []
        if isinstance(settings, list):
            blocks = settings
        elif settings is not None:
            blocks = [settings]
        # Inline blocks may instead appear as child nodes.
        blocks.extend(
            c.attributes for c in node.children
            if c.resource_type == "access_log_settings"
        )

        for block in blocks:
            if isinstance(block, dict) and str(block.get("destination_arn", "")).strip():
                return True
        return False
