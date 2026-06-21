"""SECRETS-004: Secret has no resource-based policy.

A resource policy on a secret (``aws_secretsmanager_secret_policy``) is the
defence-in-depth layer that lets you explicitly state who may read it,
independent of IAM — and, with a Deny, lets you hard-block access regardless of
what an over-broad identity policy grants. Without one, access is governed solely
by IAM and the KMS key policy, so an over-permissive IAM policy elsewhere can
reach the secret unchecked.

This is a defence-in-depth control (LOW). The rule walks the graph for an
``aws_secretsmanager_secret_policy`` attached to the secret and flags the secret
when none is found.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class SecretsNoResourcePolicy:
    """SECRETS-004: secret has no aws_secretsmanager_secret_policy."""

    rule_id = "SECRETS-004"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_secretsmanager_secret":
            return []

        if self._has_policy(node, graph):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Secret has no resource-based policy",
                description=(
                    "No aws_secretsmanager_secret_policy is attached to this "
                    "secret, so access is governed only by IAM and the KMS key "
                    "policy. There is no resource-level allow-list or Deny "
                    "backstop against an over-broad identity policy."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Attach an aws_secretsmanager_secret_policy that explicitly "
                    "limits which principals may read the secret."
                ),
                tags=frozenset(
                    {"secrets-manager", "resource-policy", "defense-in-depth", "aws"}
                ),
            )
        ]

    @staticmethod
    def _has_policy(node: IaCNode, graph: ResourceGraph) -> bool:
        for edge in graph.incoming(node.node_id):
            source = graph.get_node(edge.source)
            if (
                source is not None
                and source.resource_type == "aws_secretsmanager_secret_policy"
            ):
                return True
        return False
