"""KMS-004: KMS key deletion window is shorter than the safe maximum.

Scheduling a CMK for deletion is irreversible, and every object encrypted under
it becomes permanently unrecoverable once the key is gone. The
``deletion_window_in_days`` (7-30, default 30) is the grace period during which
a mistaken or malicious deletion can still be cancelled. A short window leaves
little time to notice and react before the key — and all data under it — is lost
forever.

This is a resilience control (LOW). The rule flags an ``aws_kms_key`` whose
``deletion_window_in_days`` is set below 30; an unset window uses the safe
30-day default and is not flagged.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_SAFE_WINDOW_DAYS = 30


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@register
class KMSShortDeletionWindow:
    """KMS-004: aws_kms_key deletion_window_in_days below 30."""

    rule_id = "KMS-004"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_kms_key":
            return []

        window = _to_int(node.attributes.get("deletion_window_in_days"))
        if window is None or window >= _SAFE_WINDOW_DAYS:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="KMS key has a short deletion window",
                description=(
                    f"deletion_window_in_days is {window} (< {_SAFE_WINDOW_DAYS}) "
                    "on this aws_kms_key. There is little time to cancel a mistaken "
                    "or malicious key deletion before the key — and everything "
                    "encrypted under it — is permanently unrecoverable."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set deletion_window_in_days = 30 to maximise the recovery "
                    "window before scheduled key deletion becomes permanent."
                ),
                tags=frozenset(
                    {"kms", "deletion-window", "resilience", "data-loss", "aws"}
                ),
            )
        ]
