"""DDB-003: DynamoDB table has no TTL configured.

Time-to-live (TTL) lets DynamoDB expire and delete items automatically once a
timestamp attribute passes. Without it, records that should be ephemeral —
sessions, tokens, PII with a retention limit — accumulate indefinitely, which
inflates cost and keeps data around longer than data-minimisation policies
allow. TTL is set through the ``ttl { enabled = true, attribute_name = ... }``
block and is off by default.

This is a data-hygiene / cost control (LOW). The rule flags an
``aws_dynamodb_table`` whose ttl block is absent or not enabled.
"""

from __future__ import annotations

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


@register
class DynamoDBTtlNotSet:
    """DDB-003: aws_dynamodb_table has no enabled ttl block."""

    rule_id = "DDB-003"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_dynamodb_table":
            return []

        for block in as_blocks(node.attributes.get("ttl")):
            if _is_enabled(block.get("enabled")):
                return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="DynamoDB table has no TTL configured",
                description=(
                    "ttl is absent or not enabled on this aws_dynamodb_table. "
                    "Items never expire automatically, so ephemeral data "
                    "accumulates, raising cost and retaining data longer than "
                    "data-minimisation policies may permit."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add a ttl { enabled = true, attribute_name = <epoch attr> } "
                    "block so DynamoDB expires items past their retention window."
                ),
                tags=frozenset(
                    {"dynamodb", "data-retention", "cost", "data-hygiene", "aws"}
                ),
            )
        ]
