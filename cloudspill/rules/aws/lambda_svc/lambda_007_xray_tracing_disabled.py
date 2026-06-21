"""LAMBDA-007: Function does not have active X-Ray tracing.

``tracing_config { mode = "Active" }`` makes Lambda emit X-Ray traces for each
invocation, giving end-to-end latency and dependency visibility across the call
chain. Beyond performance, those traces are valuable during incident response
for reconstructing what a function called and when. The default mode is
``PassThrough`` (traces only when an upstream caller already sampled).

This is an observability control (LOW). The rule flags an
``aws_lambda_function`` whose tracing_config mode is not ``Active``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register


@register
class LambdaXrayTracingDisabled:
    """LAMBDA-007: tracing_config mode is not Active."""

    rule_id = "LAMBDA-007"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_lambda_function":
            return []

        for block in as_blocks(node.attributes.get("tracing_config")):
            if str(block.get("mode", "")).strip().lower() == "active":
                return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Lambda function does not have active X-Ray tracing",
                description=(
                    'tracing_config mode is not "Active" on this '
                    "aws_lambda_function, so X-Ray traces are not emitted for every "
                    "invocation, reducing latency visibility and incident-response "
                    "context."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    'Add tracing_config { mode = "Active" } (and grant the '
                    "execution role X-Ray write permissions)."
                ),
                tags=frozenset({"lambda", "x-ray", "tracing", "observability", "aws"}),
            )
        ]
