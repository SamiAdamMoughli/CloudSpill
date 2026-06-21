"""DDB-004: DynamoDB table has streams disabled.

DynamoDB Streams emit an ordered, replayable change log of every item-level
write. Beyond change-data-capture, that stream is what powers tamper-evident
auditing and downstream security tooling — a Lambda that reacts to writes,
cross-region replication, or shipping changes to a SIEM. With streams off there
is no record of how an item reached its current state.

This is an operational / forensics control (LOW). Streams are enabled by the
``stream_enabled = true`` argument (with ``stream_view_type``); the rule flags
an ``aws_dynamodb_table`` where ``stream_enabled`` is not true.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_ENABLED_VALUES = frozenset({"true", "enabled"})


def _is_enabled(value: object) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() in _ENABLED_VALUES


@register
class DynamoDBStreamsDisabled:
    """DDB-004: aws_dynamodb_table has stream_enabled not set to true."""

    rule_id = "DDB-004"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_dynamodb_table":
            return []

        if _is_enabled(node.attributes.get("stream_enabled")):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="DynamoDB table has streams disabled",
                description=(
                    "stream_enabled is not true on this aws_dynamodb_table. There "
                    "is no change log of item-level writes, so change-driven "
                    "auditing, replication, and security tooling cannot observe "
                    "how data changes."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set stream_enabled = true and stream_view_type (e.g. "
                    "NEW_AND_OLD_IMAGES) to emit a replayable change log."
                ),
                tags=frozenset(
                    {"dynamodb", "streams", "audit", "change-data-capture", "aws"}
                ),
            )
        ]
