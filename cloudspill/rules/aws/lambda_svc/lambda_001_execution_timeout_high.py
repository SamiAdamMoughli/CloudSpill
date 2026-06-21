"""LAMBDA-001: Function timeout is very high.

A Lambda's ``timeout`` (seconds, default 3, max 900) bounds how long a single
invocation can run. A very high timeout magnifies the cost and resource impact
of a hung dependency or an attacker who can trigger slow invocations (a
Lambda-billing denial-of-wallet), and often signals work that belongs in Step
Functions or a container rather than a single function.

This is a cost / resilience signal (LOW). The rule flags an
``aws_lambda_function`` whose ``timeout`` exceeds 300 seconds (5 minutes).
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_MAX_REASONABLE_TIMEOUT = 300


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@register
class LambdaTimeoutHigh:
    """LAMBDA-001: aws_lambda_function timeout exceeds 300s."""

    rule_id = "LAMBDA-001"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_lambda_function":
            return []

        timeout = _to_int(node.attributes.get("timeout"))
        if timeout is None or timeout <= _MAX_REASONABLE_TIMEOUT:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Lambda function timeout is very high",
                description=(
                    f"timeout is {timeout}s (> {_MAX_REASONABLE_TIMEOUT}s) on this "
                    "aws_lambda_function. Long timeouts magnify the cost of hung "
                    "dependencies and slow-invocation abuse, and often signal work "
                    "better suited to Step Functions or a container."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Lower timeout to the function's real worst-case duration; for "
                    "genuinely long work use Step Functions or a container."
                ),
                tags=frozenset({"lambda", "timeout", "cost", "resilience", "aws"}),
            )
        ]
