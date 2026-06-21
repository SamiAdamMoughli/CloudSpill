"""SQS-002: SQS queue is not encrypted with a customer-managed KMS key.

An SQS queue can be encrypted at rest with SSE-SQS (an AWS-owned key, via
``sqs_managed_sse_enabled``) or SSE-KMS with a customer-managed CMK (via
``kms_master_key_id``). Only the CMK gives you a key policy gating decryption and
a CloudTrail record of it. A queue with neither — or with only SSE-SQS — has no
customer-controlled encryption boundary around its messages.

This rule flags an ``aws_sqs_queue`` with no ``kms_master_key_id``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class SQSNoCmkEncryption:
    """SQS-002: aws_sqs_queue has no kms_master_key_id."""

    rule_id = "SQS-002"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_sqs_queue":
            return []

        if str(node.attributes.get("kms_master_key_id", "")).strip():
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="SQS queue is not encrypted with a customer-managed KMS key",
                description=(
                    "kms_master_key_id is not set on this aws_sqs_queue, so its "
                    "messages are not encrypted under a customer-managed key. There "
                    "is no controllable key policy or decryption audit trail."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set kms_master_key_id to a customer-managed KMS key for "
                    "SSE-KMS encryption of the queue."
                ),
                tags=frozenset({"sqs", "encryption", "kms", "cmk", "aws"}),
            )
        ]
