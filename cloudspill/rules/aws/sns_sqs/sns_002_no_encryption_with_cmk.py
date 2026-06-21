"""SNS-002: SNS topic is not encrypted with a customer-managed KMS key.

Server-side encryption for an SNS topic is enabled by ``kms_master_key_id``.
Without it, messages are not encrypted at rest under a key you control, and there
is no key policy gating decryption or CloudTrail record of it. For topics
carrying sensitive events (PII, security alerts, internal state), a
customer-managed CMK is the controllable encryption boundary.

This rule flags an ``aws_sns_topic`` with no ``kms_master_key_id``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class SNSNoCmkEncryption:
    """SNS-002: aws_sns_topic has no kms_master_key_id."""

    rule_id = "SNS-002"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_sns_topic":
            return []

        if str(node.attributes.get("kms_master_key_id", "")).strip():
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="SNS topic is not encrypted with a customer-managed KMS key",
                description=(
                    "kms_master_key_id is not set on this aws_sns_topic, so "
                    "messages are not encrypted at rest under a customer-managed "
                    "key. There is no controllable key policy or decryption audit "
                    "trail."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set kms_master_key_id to a customer-managed KMS key for "
                    "server-side encryption of the topic."
                ),
                tags=frozenset(
                    {"sns", "encryption", "kms", "cmk", "aws"}
                ),
            )
        ]
