"""S3-012: Replication destination is not encrypted with a KMS key.

Cross-region/cross-account replication copies objects into a destination bucket.
If a replication rule's ``destination`` does not specify an
``encryption_configuration`` with a ``replica_kms_key_id``, the replicated copies
are not encrypted with a customer-managed key at the destination — so data that
was protected in the source can land in a weaker state in another region or
account, widening exposure.

This rule flags an ``aws_s3_bucket_replication_configuration`` with a rule whose
destination has no ``replica_kms_key_id``.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register


@register
class S3ReplicationUnencrypted:
    """S3-012: replication destination lacks a replica KMS key."""

    rule_id = "S3-012"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_s3_bucket_replication_configuration":
            return []

        rules = as_blocks(node.attributes.get("rule"))
        rules += [c.attributes for c in node.children if c.resource_type == "rule"]
        for rule in rules:
            for dest in as_blocks(rule.get("destination")):
                if not self._dest_encrypted(dest):
                    return [self._finding(node)]
        return []

    @staticmethod
    def _dest_encrypted(dest: dict[str, Any]) -> bool:
        for enc in as_blocks(dest.get("encryption_configuration")):
            if str(enc.get("replica_kms_key_id", "")).strip():
                return True
        return bool(str(dest.get("replica_kms_key_id", "")).strip())

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="S3 replication destination is not KMS-encrypted",
            description=(
                "A replication rule's destination has no replica_kms_key_id, so "
                "replicated objects are not encrypted with a customer-managed key "
                "at the destination — data protected in the source can land weaker "
                "in another region or account."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Add an encryption_configuration { replica_kms_key_id = <cmk> } to "
                "each replication rule destination (and enable replica modifications "
                "/ SSE-KMS objects via source_selection_criteria)."
            ),
            tags=frozenset({"s3", "replication", "encryption", "kms", "aws"}),
        )
