"""SNS-001: SNS topic policy allows public access.

An SNS topic policy with an ``Allow`` statement granting a wildcard principal
(``"*"`` / ``{"AWS": "*"}``) and no ``Condition`` lets anyone publish to (or
subscribe to) the topic. Public publish enables spam and injection of forged
events into downstream consumers; public subscribe can leak every message to an
attacker's endpoint.

This rule flags a wildcard-principal Allow (with no Condition) on an
``aws_sns_topic_policy`` or on the inline ``policy`` of an ``aws_sns_topic``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.sns_sqs.messaging import policy_allows_public
from cloudspill.rules.base import register

_TARGET_TYPES = frozenset({"aws_sns_topic_policy", "aws_sns_topic"})


@register
class SNSTopicPolicyPublic:
    """SNS-001: topic policy allows a wildcard principal."""

    rule_id = "SNS-001"
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
                title="SNS topic policy allows public access",
                description=(
                    "An Allow statement on this SNS topic grants a wildcard "
                    "principal with no Condition, letting anyone publish to or "
                    "subscribe to the topic — enabling forged events or message "
                    "leakage."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Scope the topic policy Principal to specific account/role "
                    "ARNs, or constrain the wildcard with a Condition (e.g. "
                    "aws:SourceArn, aws:PrincipalOrgID)."
                ),
                tags=frozenset(
                    {"sns", "topic-policy", "public-access", "messaging", "aws"}
                ),
            )
        ]
