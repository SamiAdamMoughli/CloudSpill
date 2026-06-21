"""DDB-001: DynamoDB table has point-in-time recovery disabled.

Point-in-time recovery (PITR) keeps continuous backups of a table for the last
35 days, letting you restore to any second in that window after an accidental
write, a bad migration, or ransomware-style tampering. It is configured through
the ``point_in_time_recovery { enabled = true }`` block and is **off by
default**.

This rule flags an ``aws_dynamodb_table`` whose PITR block is absent or whose
``enabled`` is not true.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register

_ENABLED_VALUES = frozenset({"true", "enabled"})


def _is_enabled(value: object) -> bool:
    """True if an hcl2 enable flag is a true-y bool or 'true'/'enabled' string."""
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() in _ENABLED_VALUES


@register
class DynamoDBPitrDisabled:
    """DDB-001: aws_dynamodb_table has point_in_time_recovery disabled."""

    rule_id = "DDB-001"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_dynamodb_table":
            return []

        for block in as_blocks(node.attributes.get("point_in_time_recovery")):
            if _is_enabled(block.get("enabled")):
                return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="DynamoDB table has point-in-time recovery disabled",
                description=(
                    "point_in_time_recovery is absent or not enabled on this "
                    "aws_dynamodb_table. There are no continuous backups, so an "
                    "accidental or malicious write cannot be rolled back."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add a point_in_time_recovery { enabled = true } block to the "
                    "table so it keeps continuous backups for the last 35 days."
                ),
                tags=frozenset({"dynamodb", "backup", "recovery", "resilience", "aws"}),
            )
        ]
