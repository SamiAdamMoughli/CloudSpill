"""SECRETS-002: Secret is not encrypted with a customer-managed KMS key.

Every Secrets Manager secret is encrypted, but by default with the AWS-managed
``aws/secretsmanager`` key, which you cannot put a key policy on or audit
independently. Setting ``kms_key_id`` to a customer-managed CMK adds a second
access boundary — reading the secret then also requires ``kms:Decrypt`` on that
key — plus CloudTrail visibility of every decryption and controlled key access.

This rule flags an ``aws_secretsmanager_secret`` with no ``kms_key_id``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class SecretsNotCustomKmsEncrypted:
    """SECRETS-002: aws_secretsmanager_secret has no kms_key_id."""

    rule_id = "SECRETS-002"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_secretsmanager_secret":
            return []

        if str(node.attributes.get("kms_key_id", "")).strip():
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Secret is not encrypted with a customer-managed KMS key",
                description=(
                    "kms_key_id is not set on this aws_secretsmanager_secret, so it "
                    "uses the AWS-managed key. There is no independent key policy "
                    "gating decryption and no separate decrypt audit trail."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set kms_key_id to a customer-managed KMS key whose policy "
                    "restricts kms:Decrypt to the principals allowed to read the "
                    "secret."
                ),
                tags=frozenset(
                    {"secrets-manager", "encryption", "kms", "cmk", "aws"}
                ),
            )
        ]
