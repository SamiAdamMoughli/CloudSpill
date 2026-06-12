"""APIGW-005: API Gateway integration uses default credential behavior.

An ``aws_api_gateway_integration`` should assume an explicit, least-privilege
execution role (the ``credentials`` field = an IAM role ARN) when it calls an
AWS service. Two patterns deviate from that and are flagged here:

1. **Caller-credentials passthrough** — ``credentials`` set to the wildcard
   ``arn:aws:iam::*:user/*``. API Gateway forwards the *incoming caller's* IAM
   credentials to the backend instead of using a scoped role, so the backend
   inherits whatever permissions the caller happens to hold. Flagged for any
   AWS integration type.

2. **No explicit execution role** — a direct AWS service integration
   (``type = "AWS"``) with no ``credentials`` at all, relying on default
   behavior rather than a dedicated role. (``AWS_PROXY`` / Lambda integrations
   normally grant access via ``aws_lambda_permission`` and are not flagged for
   a missing role.)

HTTP, HTTP_PROXY, and MOCK integrations have no execution-role concept and are
ignored.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

# Integration types that call AWS services and therefore have an execution role.
_AWS_INTEGRATION_TYPES = frozenset({"AWS", "AWS_PROXY"})

# Special credentials value meaning "pass the caller's IAM identity through".
_CALLER_PASSTHROUGH = "arn:aws:iam::*:user/*"


@register
class APIGatewayDefaultExecutionRole:
    """APIGW-005: Integration relies on default credentials, not an explicit role."""

    rule_id = "APIGW-005"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_api_gateway_integration":
            return []

        integration_type = str(node.attributes.get("type", "")).upper()
        if integration_type not in _AWS_INTEGRATION_TYPES:
            return []

        credentials = str(node.attributes.get("credentials", "")).strip()

        # 1. Caller-credentials passthrough (dangerous on any AWS integration).
        if credentials == _CALLER_PASSTHROUGH:
            return [
                self._finding(
                    node,
                    detail=(
                        "credentials is the wildcard ARN arn:aws:iam::*:user/*, so "
                        "API Gateway forwards the caller's IAM credentials to the "
                        "backend. The backend inherits the caller's permissions "
                        "instead of using a scoped execution role."
                    ),
                )
            ]

        # 2. Direct AWS service integration with no explicit execution role.
        if not credentials and integration_type == "AWS":
            return [
                self._finding(
                    node,
                    detail=(
                        "This AWS service integration sets no credentials, relying "
                        "on default behavior rather than a dedicated least-privilege "
                        "execution role."
                    ),
                )
            ]

        return []

    def _finding(self, node: IaCNode, detail: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="API Gateway integration uses default execution credentials",
            description=detail,
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Set credentials to the ARN of a dedicated IAM role scoped to only "
                "the actions this integration needs."
            ),
            tags=frozenset(
                {"api-gateway", "iam", "least-privilege", "execution-role", "aws"}
            ),
        )
