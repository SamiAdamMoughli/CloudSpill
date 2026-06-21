"""EC2-005: Instance block device is not encrypted.

An ``aws_instance``'s ``root_block_device`` and ``ebs_block_device`` blocks each
take an ``encrypted`` flag. When a block device is declared without
``encrypted = true``, the volume's data — including anything the OS swaps or
logs to disk — is written unencrypted at rest, so a snapshot or detached-volume
leak exposes it directly.

This rule flags an ``aws_instance`` that declares a block device whose
``encrypted`` is not true. (Account-wide default encryption is covered
separately by EC2-009.)
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register

_DEVICE_KEYS = ("root_block_device", "ebs_block_device")


def _is_true(value: object) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() == "true"


@register
class EC2NoEbsEncryption:
    """EC2-005: aws_instance has a block device without encryption."""

    rule_id = "EC2-005"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_instance":
            return []

        for key in _DEVICE_KEYS:
            blocks = as_blocks(node.attributes.get(key))
            blocks += [c.attributes for c in node.children if c.resource_type == key]
            for block in blocks:
                if not _is_true(block.get("encrypted")):
                    return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Instance block device is not encrypted",
            description=(
                "A root_block_device or ebs_block_device on this aws_instance "
                "does not set encrypted = true, so the volume is unencrypted at "
                "rest and its data is exposed through any snapshot or volume leak."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Set encrypted = true on every root_block_device and "
                "ebs_block_device (optionally with a kms_key_id for a CMK)."
            ),
            tags=frozenset({"ec2", "ebs", "encryption", "data-at-rest", "aws"}),
        )
