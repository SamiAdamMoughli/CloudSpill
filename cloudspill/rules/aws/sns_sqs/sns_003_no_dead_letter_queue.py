"""SNS-003: SNS subscription has no dead-letter queue.

An SNS subscription's ``redrive_policy`` names an SQS dead-letter queue that
captures messages SNS could not deliver to the endpoint after retries. Without
it, undeliverable messages are dropped silently — losing the data and any signal
that delivery is failing, which hides outages and complicates incident
reconstruction.

This is a resilience / observability control (LOW). The rule flags an
``aws_sns_topic_subscription`` with no ``redrive_policy``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class SNSSubscriptionNoDlq:
    """SNS-003: aws_sns_topic_subscription has no redrive_policy."""

    rule_id = "SNS-003"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_sns_topic_subscription":
            return []

        if str(node.attributes.get("redrive_policy", "")).strip():
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="SNS subscription has no dead-letter queue",
                description=(
                    "This aws_sns_topic_subscription has no redrive_policy, so "
                    "messages that fail delivery after retries are dropped "
                    "silently — losing the data and any signal that delivery is "
                    "failing."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set redrive_policy on the subscription to an SQS dead-letter "
                    "queue that captures undeliverable messages."
                ),
                tags=frozenset(
                    {"sns", "dead-letter-queue", "resilience", "observability", "aws"}
                ),
            )
        ]
