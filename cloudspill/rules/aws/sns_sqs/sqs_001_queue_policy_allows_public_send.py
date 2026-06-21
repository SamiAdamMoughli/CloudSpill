"""SQS-001: SQS queue policy allows public access.

An SQS queue policy with an ``Allow`` statement granting a wildcard principal
(``"*"`` / ``{"AWS": "*"}``) and no ``Condition`` lets anyone send to (or receive
from) the queue. Public send lets an attacker flood the queue or inject crafted
messages into downstream processing; public receive can leak in-flight messages.

This rule flags a wildcard-principal Allow (with no Condition) on an
``aws_sqs_queue_policy`` or on the inline ``policy`` of an ``aws_sqs_queue``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.sns_sqs.messaging import policy_allows_public
from cloudspill.rules.base import register

_TARGET_TYPES = frozenset({"aws_sqs_queue_policy", "aws_sqs_queue"})


@register
class SQSQueuePolicyPublic:
    """SQS-001: queue policy allows a wildcard principal."""

    rule_id = "SQS-001"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _TARGET_TYPES:
            return []
        if not policy_allows_public(node.attributes.get("policy", "")):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="SQS queue policy allows public access",
                description=(
                    "An Allow statement on this SQS queue grants a wildcard "
                    "principal with no Condition, letting anyone send to or receive "
                    "from the queue — enabling message flooding, injection, or "
                    "leakage of in-flight messages."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Scope the queue policy Principal to specific account/role "
                    "ARNs, or constrain the wildcard with a Condition (e.g. "
                    "aws:SourceArn for the producing service)."
                ),
                tags=frozenset(
                    {"sqs", "queue-policy", "public-access", "messaging", "aws"}
                ),
            )
        ]
