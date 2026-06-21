"""SECRETS-005: Rotation interval is too long.

Configuring rotation is only half the control — the interval matters. An
``aws_secretsmanager_secret_rotation`` whose ``rotation_rules.automatically_after_days``
is large means the same secret value stays live for months, so a leaked
credential has a correspondingly long window of use before it is replaced. A
common baseline is to rotate at least every 90 days.

This rule flags an ``aws_secretsmanager_secret_rotation`` whose
``automatically_after_days`` exceeds 90. (Rotations defined only by a
``schedule_expression`` cron are not evaluated here.)
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register

_MAX_ROTATION_DAYS = 90


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@register
class SecretsRotationIntervalTooLong:
    """SECRETS-005: rotation_rules.automatically_after_days over 90."""

    rule_id = "SECRETS-005"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_secretsmanager_secret_rotation":
            return []

        blocks = as_blocks(node.attributes.get("rotation_rules"))
        blocks += [
            c.attributes for c in node.children if c.resource_type == "rotation_rules"
        ]
        for block in blocks:
            days = _to_int(block.get("automatically_after_days"))
            if days is not None and days > _MAX_ROTATION_DAYS:
                return [self._finding(node, days)]
        return []

    def _finding(self, node: IaCNode, days: int) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Secret rotation interval is too long",
            description=(
                f"rotation_rules.automatically_after_days is {days} "
                f"(> {_MAX_ROTATION_DAYS}). The secret value stays live for "
                "months, giving a leaked credential a long window of use before "
                "rotation."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                f"Lower automatically_after_days to {_MAX_ROTATION_DAYS} or less "
                "(or use a schedule_expression with a suitable cadence)."
            ),
            tags=frozenset(
                {"secrets-manager", "rotation", "credential-hygiene", "aws"}
            ),
        )
