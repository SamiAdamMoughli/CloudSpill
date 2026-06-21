"""KMS-001: KMS key policy allows a wildcard principal to use the key.

A key policy is the last line of defence on a CMK: even if IAM is misconfigured,
the key policy decides who can call ``kms:Decrypt`` (and friends). An ``Allow``
statement with a wildcard principal (``"*"`` / ``{"AWS": "*"}``) and no
``Condition`` lets any AWS principal use the key — which means everything
encrypted under it (S3 objects, EBS volumes, secrets) can be decrypted by anyone
who can reach those ciphertexts.

This rule flags an ``aws_kms_key`` whose ``policy`` has an Allow statement that
combines a wildcard principal with a decrypt/use action (``kms:Decrypt``,
``kms:ReEncrypt*``, ``kms:*``, or ``*``) and no constraining Condition.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.policy import extract_statements, is_wildcard_principal
from cloudspill.rules.base import register

_USE_ACTION_HINTS = ("kms:decrypt", "kms:reencrypt", "kms:*", "*")


def _as_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)] if value is not None else []


def _grants_use(actions: list[str]) -> bool:
    for action in actions:
        lowered = action.strip().lower()
        if lowered in ("*", "kms:*") or lowered.startswith(
            ("kms:decrypt", "kms:reencrypt")
        ):
            return True
    return False


@register
class KMSKeyPolicyPublicDecrypt:
    """KMS-001: aws_kms_key policy allows a wildcard principal to decrypt."""

    rule_id = "KMS-001"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_kms_key":
            return []

        for stmt in extract_statements(node.attributes.get("policy", "")):
            if stmt.get("Effect") != "Allow":
                continue
            if stmt.get("Condition"):
                continue
            if not is_wildcard_principal(stmt.get("Principal")):
                continue
            if _grants_use(_as_list(stmt.get("Action"))):
                return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="KMS key policy allows a wildcard principal to use the key",
            description=(
                "An Allow statement in this key policy grants a wildcard principal "
                "a decrypt/use action with no Condition. Any AWS principal can use "
                "the key, so everything encrypted under it is exposed."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Scope the key policy Principal to specific account/role ARNs, or "
                "constrain the wildcard with a Condition (e.g. aws:PrincipalOrgID, "
                "kms:ViaService)."
            ),
            tags=frozenset({"kms", "key-policy", "public-access", "encryption", "aws"}),
        )
