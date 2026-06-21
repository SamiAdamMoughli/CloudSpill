"""KMS-003: KMS grant has no constraints.

An ``aws_kms_grant`` delegates key operations to a grantee principal. Without a
``constraints`` block (an encryption-context condition), the grant lets the
grantee perform those operations on *any* ciphertext under the key, not just the
specific context it was meant for. Unconstrained grants are broad, easy to
overlook, and hard to audit — they are a common way standing key access creeps
in outside the key policy.

This rule flags an ``aws_kms_grant`` that declares no ``constraints``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register


@register
class KMSGrantNotConstrained:
    """KMS-003: aws_kms_grant has no constraints block."""

    rule_id = "KMS-003"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_kms_grant":
            return []

        blocks = as_blocks(node.attributes.get("constraints"))
        blocks += [
            c.attributes for c in node.children if c.resource_type == "constraints"
        ]
        if blocks:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="KMS grant has no encryption-context constraints",
                description=(
                    "This aws_kms_grant declares no constraints block, so the "
                    "grantee can use the granted operations on any ciphertext under "
                    "the key. Unconstrained grants are broad and hard to audit."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add a constraints block (encryption_context_equals or "
                    "encryption_context_subset) so the grant only applies to the "
                    "intended encryption context."
                ),
                tags=frozenset(
                    {"kms", "grant", "least-privilege", "auditability", "aws"}
                ),
            )
        ]
