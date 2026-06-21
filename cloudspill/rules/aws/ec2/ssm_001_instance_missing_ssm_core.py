"""SSM-001: Instance has no instance profile for SSM management.

AWS Systems Manager (Session Manager, Patch Manager, inventory) needs the SSM
agent on the instance to authenticate with an instance-profile role carrying
``AmazonSSMManagedInstanceCore``. An ``aws_instance`` with no
``iam_instance_profile`` at all cannot use SSM, which usually means operators
fall back to opening SSH — losing keyless, audited, port-free access and patch
automation.

This rule flags an ``aws_instance`` that declares no ``iam_instance_profile``.
(Whether an attached profile's role actually grants the SSM core policy is a
deeper IAM check; the absence of any profile is the clear, high-signal case.)
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class EC2InstanceMissingSsmCore:
    """SSM-001: aws_instance has no iam_instance_profile."""

    rule_id = "SSM-001"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_instance":
            return []

        if str(node.attributes.get("iam_instance_profile", "")).strip():
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Instance has no instance profile for SSM management",
                description=(
                    "This aws_instance declares no iam_instance_profile, so it "
                    "cannot register with AWS Systems Manager. Operators typically "
                    "fall back to SSH, losing keyless, audited Session Manager "
                    "access and automated patching."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Attach an iam_instance_profile whose role includes the "
                    "AmazonSSMManagedInstanceCore managed policy so the instance "
                    "can be managed through SSM."
                ),
                tags=frozenset(
                    {"ec2", "ssm", "instance-profile", "access-management", "aws"}
                ),
            )
        ]
