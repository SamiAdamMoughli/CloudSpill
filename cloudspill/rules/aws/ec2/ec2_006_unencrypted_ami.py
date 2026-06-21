"""EC2-006: AMI backing snapshot is not encrypted.

An ``aws_ami`` (or ``aws_ami_copy``) defines its backing volumes through
``ebs_block_device`` blocks, each with an ``encrypted`` flag. An AMI whose
snapshots are unencrypted produces unencrypted root volumes on every instance
launched from it, and the AMI's snapshots themselves are readable at rest —
especially dangerous if the AMI is ever shared.

This rule flags an ``aws_ami``/``aws_ami_copy`` whose block-device encryption
is not enabled.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register

_TARGET_TYPES = frozenset({"aws_ami", "aws_ami_copy"})


def _is_true(value: object) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() == "true"


@register
class EC2UnencryptedAmi:
    """EC2-006: aws_ami backing snapshot lacks encryption."""

    rule_id = "EC2-006"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _TARGET_TYPES:
            return []

        # aws_ami_copy has a top-level `encrypted` argument.
        if node.resource_type == "aws_ami_copy" and _is_true(
            node.attributes.get("encrypted")
        ):
            return []

        blocks = as_blocks(node.attributes.get("ebs_block_device"))
        blocks += [
            c.attributes for c in node.children if c.resource_type == "ebs_block_device"
        ]

        if node.resource_type == "aws_ami_copy" and not blocks:
            # encrypted flag absent and no block devices declared → flag the copy
            return [self._finding(node)]

        for block in blocks:
            if not _is_true(block.get("encrypted")):
                return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="AMI backing snapshot is not encrypted",
            description=(
                "This AMI's backing snapshot is not encrypted. Instances launched "
                "from it get unencrypted root volumes, and the AMI's snapshots are "
                "readable at rest — a serious exposure if the AMI is shared."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Set encrypted = true on the AMI's ebs_block_device blocks (or on "
                "aws_ami_copy directly) so the backing snapshots are encrypted."
            ),
            tags=frozenset({"ec2", "ami", "encryption", "data-at-rest", "aws"}),
        )
