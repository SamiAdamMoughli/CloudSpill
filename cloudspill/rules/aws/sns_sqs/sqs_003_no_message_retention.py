"""SQS-003: SQS queue retains messages for too short a period.

``message_retention_seconds`` (60-1,209,600; default 345,600 = 4 days) controls
how long SQS keeps a message before discarding it. A very short retention means
messages are dropped quickly if consumers fall behind or are down for
maintenance, losing data and any chance to reprocess — and shrinking the window
to investigate what was in the queue during an incident.

This is a resilience control (LOW). The rule flags an ``aws_sqs_queue`` whose
``message_retention_seconds`` is explicitly set below one day (86,400). An unset
value uses the 4-day default and is not flagged.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_MIN_RETENTION_SECONDS = 86_400


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@register
class SQSShortMessageRetention:
    """SQS-003: message_retention_seconds below one day."""

    rule_id = "SQS-003"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_sqs_queue":
            return []

        retention = _to_int(node.attributes.get("message_retention_seconds"))
        if retention is None or retention >= _MIN_RETENTION_SECONDS:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="SQS queue retains messages for too short a period",
                description=(
                    f"message_retention_seconds is {retention} (< "
                    f"{_MIN_RETENTION_SECONDS}, one day) on this aws_sqs_queue. "
                    "Messages are discarded quickly if consumers fall behind, "
                    "losing data and shrinking the incident-investigation window."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Raise message_retention_seconds to a value that tolerates "
                    "consumer downtime (the default is 4 days; the maximum is 14)."
                ),
                tags=frozenset(
                    {"sqs", "message-retention", "resilience", "aws"}
                ),
            )
        ]
