"""EBS-003: AMI / EBS snapshot is shared publicly.

Sharing is made public by granting launch/create-volume permission to the
special group ``"all"`` rather than to specific account IDs:

* ``aws_ami_launch_permission`` with ``group = "all"`` makes an AMI — and the
  EBS snapshots backing it — readable by every AWS account, and
* ``aws_snapshot_create_volume_permission`` / ``aws_ebs_snapshot`` constructs
  that grant the ``all`` group do the same for a bare snapshot.

A public AMI or snapshot leaks whatever is on the disk image (baked-in secrets,
source, customer data) to the entire world. This rule flags any such resource
that grants access to the ``all`` group.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_str_list
from cloudspill.rules.base import register

_TARGET_TYPES = frozenset(
    {
        "aws_ami_launch_permission",
        "aws_snapshot_create_volume_permission",
    }
)


@register
class EBSSnapshotPublicAccess:
    """EBS-003: AMI/snapshot permission grants the 'all' group (public)."""

    rule_id = "EBS-003"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _TARGET_TYPES:
            return []

        if not self._is_public(node):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="AMI or EBS snapshot is shared publicly",
                description=(
                    "This permission grants the special 'all' group, making the "
                    "AMI/snapshot — and the disk image behind it — readable by "
                    "every AWS account. Any secrets, source, or data on the image "
                    "are exposed publicly."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Remove the 'all' group grant and share only with specific, "
                    "trusted account IDs (or keep the image private)."
                ),
                tags=frozenset(
                    {"ebs", "ami", "snapshot", "public-access", "aws"}
                ),
            )
        ]

    @staticmethod
    def _is_public(node: IaCNode) -> bool:
        attrs = node.attributes
        if str(attrs.get("group", "")).strip().lower() == "all":
            return True
        # Some forms express it as a list of groups.
        return "all" in {g.strip().lower() for g in as_str_list(attrs.get("groups"))}
