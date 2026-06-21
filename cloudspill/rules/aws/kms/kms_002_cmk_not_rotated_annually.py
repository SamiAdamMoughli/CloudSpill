"""KMS-002: Customer-managed key does not have automatic rotation enabled.

For a symmetric CMK, ``enable_key_rotation = true`` makes KMS rotate the backing
key material once a year automatically, limiting how much data is protected by
any single key version and bounding the blast radius if key material is ever
compromised. It is off by default and costs nothing to turn on.

Only symmetric encrypt/decrypt CMKs support rotation, so this rule skips
asymmetric keys (``customer_master_key_spec`` other than
``SYMMETRIC_DEFAULT``) and sign/verify keys (``key_usage = "SIGN_VERIFY"``). It
flags a rotatable ``aws_kms_key`` whose ``enable_key_rotation`` is not true.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


def _is_true(value: object) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() == "true"


@register
class KMSCmkNotRotated:
    """KMS-002: rotatable aws_kms_key has enable_key_rotation not true."""

    rule_id = "KMS-002"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_kms_key":
            return []

        if not self._is_rotatable(node):
            return []

        if _is_true(node.attributes.get("enable_key_rotation")):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="KMS CMK does not have automatic key rotation enabled",
                description=(
                    "enable_key_rotation is not true on this symmetric "
                    "aws_kms_key, so its key material is never rotated. A single "
                    "key version protects all data indefinitely, enlarging the "
                    "blast radius of any key compromise."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set enable_key_rotation = true so KMS rotates the key "
                    "material annually."
                ),
                tags=frozenset(
                    {"kms", "key-rotation", "encryption", "cmk", "aws"}
                ),
            )
        ]

    @staticmethod
    def _is_rotatable(node: IaCNode) -> bool:
        attrs = node.attributes
        spec = str(attrs.get("customer_master_key_spec", "SYMMETRIC_DEFAULT")).strip().upper()
        usage = str(attrs.get("key_usage", "ENCRYPT_DECRYPT")).strip().upper()
        return spec == "SYMMETRIC_DEFAULT" and usage == "ENCRYPT_DECRYPT"
