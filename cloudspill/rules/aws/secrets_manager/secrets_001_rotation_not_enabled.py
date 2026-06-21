"""SECRETS-001: Secret has no automatic rotation configured.

Automatic rotation (an ``aws_secretsmanager_secret_rotation`` tied to the secret)
periodically replaces the secret value via a Lambda, so a leaked credential has a
bounded useful life and stale long-lived secrets do not accumulate. A secret with
no rotation keeps the same value indefinitely — if it ever leaks, it stays valid
until someone notices and rotates it by hand.

This rule walks the graph for an ``aws_secretsmanager_secret_rotation`` that
references the secret; finding none, it flags the
``aws_secretsmanager_secret``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class SecretsRotationNotEnabled:
    """SECRETS-001: secret has no aws_secretsmanager_secret_rotation."""

    rule_id = "SECRETS-001"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_secretsmanager_secret":
            return []

        if self._has_rotation(node, graph):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Secret has no automatic rotation configured",
                description=(
                    "No aws_secretsmanager_secret_rotation references this secret, "
                    "so its value is never rotated. A leaked credential stays valid "
                    "indefinitely until rotated by hand."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add an aws_secretsmanager_secret_rotation with a rotation "
                    "Lambda and rotation_rules to rotate the secret on a schedule."
                ),
                tags=frozenset(
                    {"secrets-manager", "rotation", "credential-hygiene", "aws"}
                ),
            )
        ]

    @staticmethod
    def _has_rotation(node: IaCNode, graph: ResourceGraph) -> bool:
        for edge in graph.incoming(node.node_id):
            source = graph.get_node(edge.source)
            if (
                source is not None
                and source.resource_type == "aws_secretsmanager_secret_rotation"
            ):
                return True
        return False
