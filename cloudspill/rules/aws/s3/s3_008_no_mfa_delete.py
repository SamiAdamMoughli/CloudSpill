"""S3-008: Bucket versioning does not have MFA delete enabled.

MFA delete requires a valid MFA token to permanently delete an object version or
suspend versioning. On a bucket holding important or compliance-relevant data, it
is the control that stops an attacker (or compromised automation) with delete
permissions from wiping object history to cover their tracks. It is configured on
the versioning settings, inline (``versioning { mfa_delete = true }``) or via
``aws_s3_bucket_versioning`` (``mfa_delete = "Enabled"``).

This rule flags an ``aws_s3_bucket_versioning`` (or inline ``aws_s3_bucket``
versioning) where MFA delete is not enabled.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register

_ENABLED = frozenset({"true", "enabled"})


def _mfa_enabled(value: object) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() in _ENABLED


@register
class S3NoMfaDelete:
    """S3-008: versioning configuration lacks MFA delete."""

    rule_id = "S3-008"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type == "aws_s3_bucket_versioning":
            blocks = as_blocks(node.attributes.get("versioning_configuration"))
            if any(_mfa_enabled(b.get("mfa_delete")) for b in blocks):
                return []
            return [self._finding(node)]

        if node.resource_type == "aws_s3_bucket":
            blocks = as_blocks(node.attributes.get("versioning"))
            if not blocks:
                return []  # versioning absence is S3-005's concern
            if any(_mfa_enabled(b.get("mfa_delete")) for b in blocks):
                return []
            return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="S3 bucket versioning has no MFA delete",
            description=(
                "MFA delete is not enabled on this bucket's versioning, so a "
                "principal with delete permissions can permanently remove object "
                "versions and erase history without an MFA challenge."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                'Enable MFA delete (mfa_delete = "Enabled") on the bucket '
                "versioning configuration (applied with the root account's MFA)."
            ),
            tags=frozenset(
                {"s3", "mfa-delete", "versioning", "tamper-resistance", "aws"}
            ),
        )
