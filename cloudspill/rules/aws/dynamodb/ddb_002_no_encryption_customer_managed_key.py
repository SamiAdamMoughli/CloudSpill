"""DDB-002: DynamoDB table is not encrypted with a customer-managed KMS key.

Every DynamoDB table is encrypted at rest, but by default with an AWS-owned key
that you cannot see, audit, or control. The ``server_side_encryption`` block
with ``enabled = true`` and a ``kms_key_arn`` switches the table to a
customer-managed CMK, giving you a key policy (who can decrypt), rotation
control, and CloudTrail visibility of every Decrypt call.

This rule flags an ``aws_dynamodb_table`` that has no server_side_encryption
block enabling a customer-managed ``kms_key_arn``.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register

_ENABLED_VALUES = frozenset({"true", "enabled"})


def _is_enabled(value: object) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() in _ENABLED_VALUES


def uses_customer_managed_cmk(node: IaCNode) -> bool:
    """True if a table's server_side_encryption enables a customer-managed CMK.

    Shared with DDB-005, which checks the same property from the GSI angle.
    """
    for block in as_blocks(node.attributes.get("server_side_encryption")):
        if not _is_enabled(block.get("enabled")):
            continue
        kms_key_arn: Any = block.get("kms_key_arn")
        if kms_key_arn is not None and str(kms_key_arn).strip():
            return True
    return False


@register
class DynamoDBNoCustomerManagedKey:
    """DDB-002: aws_dynamodb_table not encrypted with a customer-managed CMK."""

    rule_id = "DDB-002"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_dynamodb_table":
            return []

        if uses_customer_managed_cmk(node):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="DynamoDB table is not encrypted with a customer-managed KMS key",
                description=(
                    "This aws_dynamodb_table has no server_side_encryption block "
                    "enabling a customer-managed kms_key_arn, so it falls back to "
                    "the AWS-owned key. You get no key policy, no controlled "
                    "rotation, and no CloudTrail visibility of decryption."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add server_side_encryption { enabled = true, kms_key_arn = "
                    "<cmk arn> } referencing a customer-managed KMS key with a "
                    "scoped key policy."
                ),
                tags=frozenset(
                    {"dynamodb", "encryption", "kms", "cmk", "aws"}
                ),
            )
        ]
