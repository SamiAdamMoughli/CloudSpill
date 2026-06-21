"""S3-010: Bucket policy does not deny unencrypted uploads.

Default bucket encryption protects objects regardless, but the policy-level
control — a ``Deny`` on ``s3:PutObject`` when the
``s3:x-amz-server-side-encryption`` header is missing or wrong — is what actually
*rejects* a plaintext upload at request time, and proves enforcement for
compliance. A bucket policy without that Deny accepts whatever encryption (or
none) the caller specifies.

This rule flags an ``aws_s3_bucket_policy`` (or inline ``aws_s3_bucket`` policy)
that has statements but none denying uploads based on the server-side-encryption
condition.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.policy import extract_statements
from cloudspill.rules.base import register


def _condition_keys(stmt: dict[str, Any]) -> set[str]:
    condition = stmt.get("Condition")
    keys: set[str] = set()
    if isinstance(condition, dict):
        for checks in condition.values():
            if isinstance(checks, dict):
                keys.update(str(k).lower() for k in checks)
    return keys


@register
class S3AllowsUnencryptedUploads:
    """S3-010: policy does not deny unencrypted PutObject."""

    rule_id = "S3-010"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in ("aws_s3_bucket_policy", "aws_s3_bucket"):
            return []

        statements = extract_statements(node.attributes.get("policy", ""))
        if not statements:
            return []  # no policy → S3-006 covers the missing-policy case

        enforces = any(
            stmt.get("Effect") == "Deny"
            and any(
                "x-amz-server-side-encryption" in key for key in _condition_keys(stmt)
            )
            for stmt in statements
        )
        if enforces:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="S3 bucket policy does not deny unencrypted uploads",
                description=(
                    "The bucket policy has no Deny on s3:PutObject keyed on "
                    "s3:x-amz-server-side-encryption, so plaintext uploads are not "
                    "rejected at request time and encryption enforcement is not "
                    "provable."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add a Deny statement on s3:PutObject when "
                    "s3:x-amz-server-side-encryption is missing or not the required "
                    "algorithm (aws:kms)."
                ),
                tags=frozenset(
                    {"s3", "bucket-policy", "encryption", "upload-enforcement", "aws"}
                ),
            )
        ]
