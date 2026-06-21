"""S3-013: Bucket policy does not deny non-TLS (HTTP) requests.

S3 accepts both HTTP and HTTPS by default. The control that forces encryption in
transit is a bucket-policy ``Deny`` on all actions when
``aws:SecureTransport`` is ``false`` — without it, clients can read and write
objects over plaintext HTTP, exposing data and credentials to network
interception. This is the well-known CIS S3 "deny non-SSL requests" baseline.

This rule flags an ``aws_s3_bucket_policy`` (or inline ``aws_s3_bucket`` policy)
that has statements but none denying requests on the ``aws:SecureTransport``
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
class S3AllowsNonSsl:
    """S3-013: policy does not deny non-TLS requests."""

    rule_id = "S3-013"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in ("aws_s3_bucket_policy", "aws_s3_bucket"):
            return []

        statements = extract_statements(node.attributes.get("policy", ""))
        if not statements:
            return []  # no policy → S3-006 covers the missing-policy case

        enforces = any(
            stmt.get("Effect") == "Deny"
            and any("securetransport" in key for key in _condition_keys(stmt))
            for stmt in statements
        )
        if enforces:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="S3 bucket policy does not deny non-TLS requests",
                description=(
                    "The bucket policy has no Deny keyed on aws:SecureTransport = "
                    "false, so objects can be read and written over plaintext HTTP, "
                    "exposing data and credentials to network interception."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add a Deny statement on s3:* (Principal *) when "
                    "aws:SecureTransport is false to require HTTPS."
                ),
                tags=frozenset(
                    {"s3", "bucket-policy", "in-transit-encryption", "tls", "aws"}
                ),
            )
        ]
