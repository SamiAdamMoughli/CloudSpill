"""DDB-005: DynamoDB global secondary indexes are not under a customer key.

A global secondary index (GSI) materialises a second copy of the table's data
under a different key schema, and that copy inherits the table's
``server_side_encryption`` setting. So a table that defines GSIs but has no
customer-managed CMK is replicating its data into additional storage that is
protected only by the AWS-owned key — the same blind spot as DDB-002, widened
across every index copy.

This rule fires only when a table both defines one or more
``global_secondary_index`` blocks and lacks a customer-managed CMK; it reuses
DDB-002's CMK check so the two rules agree on what "encrypted with a CMK"
means.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.dynamodb.ddb_002_no_encryption_customer_managed_key import (
    uses_customer_managed_cmk,
)
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register


@register
class DynamoDBGsiNotEncrypted:
    """DDB-005: table with GSIs is not encrypted with a customer-managed CMK."""

    rule_id = "DDB-005"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_dynamodb_table":
            return []

        if not as_blocks(node.attributes.get("global_secondary_index")):
            return []  # no GSIs — nothing index-specific to flag

        if uses_customer_managed_cmk(node):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="DynamoDB global secondary indexes are not under a customer key",
                description=(
                    "This aws_dynamodb_table defines global_secondary_index "
                    "blocks but has no customer-managed CMK. Each index holds a "
                    "second copy of the data protected only by the AWS-owned key, "
                    "with no controllable key policy or decryption audit trail."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Enable server_side_encryption with a customer-managed "
                    "kms_key_arn on the table; the GSIs inherit that CMK "
                    "automatically."
                ),
                tags=frozenset(
                    {"dynamodb", "encryption", "kms", "gsi", "aws"}
                ),
            )
        ]
