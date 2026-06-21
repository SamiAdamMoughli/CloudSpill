"""APIGW-002: API Gateway REST stage is not protected by an AWS WAF Web ACL.

An API Gateway REST stage should sit behind an AWS WAF (Web Application
Firewall) Web ACL. Without one, the endpoint has no centralized layer-7
protection against application-layer vectors such as SQL injection, XSS,
credential stuffing, and high-volume layer-7 floods.

How association actually works in Terraform
-------------------------------------------
A WAF Web ACL is **not** an attribute on the stage. It is bound by a separate
association resource whose ``resource_arn`` points at the stage ARN:

    resource "aws_wafv2_web_acl_association" "x" {
      resource_arn = aws_api_gateway_stage.prod.arn   # -> edge into the stage
      web_acl_arn  = aws_wafv2_web_acl.main.arn
    }

The graph builder turns that ``resource_arn`` reference into an incoming edge
on the stage node, so this rule detects protection by looking for an incoming
edge from a WAF association resource — not by reading a stage attribute.

Scope
-----
Only ``aws_api_gateway_stage`` (REST APIs) is checked. AWS WAF does not
support HTTP or WebSocket APIs (``aws_apigatewayv2_stage``), so flagging those
would be a false positive.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

# Resource types that bind a WAF Web ACL to a regional resource such as an
# API Gateway REST stage. Covers both WAFv2 and the legacy WAF Classic.
_WAF_ASSOCIATION_TYPES = frozenset(
    {
        "aws_wafv2_web_acl_association",
        "aws_wafregional_web_acl_association",
    }
)


@register
class APIGateWayNoWafAttached:
    """APIGW-002: API Gateway REST stage lacks AWS WAF protection."""

    rule_id = "APIGW-002"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_api_gateway_stage":
            return []

        if self._has_waf_association(node, graph):
            return []

        stage_name = str(
            node.attributes.get("stage_name", "") or node.attributes.get("name", "")
        )
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title=f"API Gateway stage '{stage_name or '?'}' has no WAF Web ACL attached",
                description=(
                    "No aws_wafv2_web_acl_association (or WAF Classic equivalent) "
                    "references this stage. The endpoint is deployed without "
                    "layer-7 protection and is exposed to application-layer "
                    "attacks and high-volume layer-7 floods."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Create an aws_wafv2_web_acl_association whose resource_arn "
                    "targets this stage's ARN and whose web_acl_arn references a "
                    "WAFv2 Web ACL."
                ),
                tags=frozenset(
                    {"api-gateway", "waf", "security-defense", "aws", "layer-7"}
                ),
            )
        ]

    @staticmethod
    def _has_waf_association(node: IaCNode, graph: ResourceGraph) -> bool:
        """True if a WAF association resource references this stage.

        The association's ``resource_arn`` reference to the stage produces an
        incoming edge whose source is the association node.
        """
        for edge in graph.incoming(node.node_id):
            source = graph.get_node(edge.source)
            if source is not None and source.resource_type in _WAF_ASSOCIATION_TYPES:
                return True
        return False
