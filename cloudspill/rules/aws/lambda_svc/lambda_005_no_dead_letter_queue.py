"""LAMBDA-005: Function has no dead-letter queue.

For asynchronous invocations, a ``dead_letter_config`` (an SNS topic or SQS
queue) captures events that fail every retry. Without one, those failed events
are silently dropped — you lose both the data and any signal that processing is
failing, which hides outages and tampering and makes incident reconstruction
impossible.

This is a resilience / observability control (LOW). The rule flags an
``aws_lambda_function`` with no ``dead_letter_config`` target.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register


@register
class LambdaNoDeadLetterQueue:
    """LAMBDA-005: aws_lambda_function has no dead_letter_config."""

    rule_id = "LAMBDA-005"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_lambda_function":
            return []

        for block in as_blocks(node.attributes.get("dead_letter_config")):
            if str(block.get("target_arn", "")).strip():
                return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Lambda function has no dead-letter queue",
                description=(
                    "This aws_lambda_function has no dead_letter_config, so "
                    "asynchronous events that exhaust their retries are dropped "
                    "silently — losing the data and any signal that processing is "
                    "failing."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add a dead_letter_config with an SQS queue or SNS topic "
                    "target_arn to capture failed asynchronous invocations."
                ),
                tags=frozenset(
                    {
                        "lambda",
                        "dead-letter-queue",
                        "resilience",
                        "observability",
                        "aws",
                    }
                ),
            )
        ]
