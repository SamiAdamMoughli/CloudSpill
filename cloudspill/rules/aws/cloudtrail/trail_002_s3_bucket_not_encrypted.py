"""TRAIL-002: CloudTrail log files are not encrypted with a KMS key.

``aws_cloudtrail`` writes its log files to an S3 bucket. By default those files
get SSE-S3 (AES-256) encryption, but CloudTrail also supports SSE-KMS via the
``kms_key_id`` argument. SSE-KMS adds a customer-managed key boundary: reading
the audit logs then requires ``kms:Decrypt`` on that key, so a principal with
S3 read access alone cannot exfiltrate or tamper with the trail.

When ``kms_key_id`` is absent or empty the log files rely on SSE-S3 only, with
no separate key-policy control over who can read them. This rule flags that
case.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class CloudTrailLogsNotKmsEncrypted:
    """TRAIL-002: aws_cloudtrail has no kms_key_id (log files not SSE-KMS)."""

    rule_id = "TRAIL-002"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_cloudtrail":
            return []

        if str(node.attributes.get("kms_key_id", "")).strip():
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="CloudTrail log files are not encrypted with a KMS key",
                description=(
                    "kms_key_id is not set on this aws_cloudtrail, so log files "
                    "are protected only by SSE-S3. There is no separate KMS key "
                    "policy gating who can read the audit logs, so anyone with S3 "
                    "read access to the bucket can read them."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set kms_key_id to a customer-managed KMS key ARN whose key "
                    "policy grants CloudTrail kms:GenerateDataKey* and restricts "
                    "kms:Decrypt to the principals allowed to read the logs."
                ),
                tags=frozenset({"cloudtrail", "encryption", "kms", "audit", "aws"}),
            )
        ]
