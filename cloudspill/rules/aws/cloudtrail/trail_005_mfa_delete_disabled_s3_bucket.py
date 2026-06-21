"""TRAIL-005: CloudTrail log bucket does not have MFA Delete enabled.

MFA Delete on a versioned S3 bucket requires a valid MFA token to permanently
delete an object version or to suspend versioning. For a CloudTrail log bucket
this is the control that stops an attacker (or compromised automation) with
delete permissions from wiping the audit trail to cover their tracks — deleting
a version then needs physical possession of an MFA device.

MFA Delete is configured through bucket versioning, in one of two shapes:

* legacy inline ``versioning { mfa_delete = true }`` on the ``aws_s3_bucket``, or
* the modern ``aws_s3_bucket_versioning`` resource with
  ``versioning_configuration { mfa_delete = "Enabled" }``.

This rule resolves the trail's log bucket through the graph and flags it when
neither shape enables MFA Delete. It stays silent when the bucket cannot be
resolved from the configuration (a remote or string-only bucket name carries no
versioning block to inspect).
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register

_ENABLED_VALUES = frozenset({"true", "enabled"})


@register
class CloudTrailLogBucketNoMfaDelete:
    """TRAIL-005: aws_cloudtrail log bucket lacks MFA Delete on versioning."""

    rule_id = "TRAIL-005"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_cloudtrail":
            return []

        bucket = self._log_bucket(node, graph)
        if bucket is None or self._mfa_delete_enabled(bucket, graph):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="CloudTrail log bucket does not have MFA Delete enabled",
                description=(
                    f"The S3 bucket '{bucket.name}' that stores this trail's logs "
                    "does not enable MFA Delete on its versioning configuration. "
                    "An actor with delete permissions can permanently remove log "
                    "object versions and erase the audit trail without an MFA "
                    "challenge."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Enable versioning and MFA Delete on the log bucket: set "
                    'mfa_delete = "Enabled" in the aws_s3_bucket_versioning '
                    "versioning_configuration (it must be applied with the root "
                    "account's MFA device)."
                ),
                tags=frozenset(
                    {
                        "cloudtrail",
                        "s3",
                        "mfa-delete",
                        "audit",
                        "tamper-resistance",
                        "aws",
                    }
                ),
            )
        ]

    @staticmethod
    def _log_bucket(node: IaCNode, graph: ResourceGraph) -> IaCNode | None:
        """Resolve the aws_s3_bucket referenced by the trail's s3_bucket_name."""
        for edge in graph.outgoing(node.node_id):
            target = graph.get_node(edge.target)
            if (
                target is not None
                and target.resource_type == "aws_s3_bucket"
                and edge.attribute == "s3_bucket_name"
            ):
                return target
        return None

    @classmethod
    def _mfa_delete_enabled(cls, bucket: IaCNode, graph: ResourceGraph) -> bool:
        """True if MFA Delete is enabled inline or via aws_s3_bucket_versioning."""
        # Legacy inline: versioning { mfa_delete = true }
        for block in as_blocks(bucket.attributes.get("versioning")):
            if cls._is_enabled(block.get("mfa_delete")):
                return True

        # Modern split resource: aws_s3_bucket_versioning referencing this bucket.
        for edge in graph.incoming(bucket.node_id):
            source = graph.get_node(edge.source)
            if source is None or source.resource_type != "aws_s3_bucket_versioning":
                continue
            for cfg in as_blocks(source.attributes.get("versioning_configuration")):
                if cls._is_enabled(cfg.get("mfa_delete")):
                    return True
        return False

    @staticmethod
    def _is_enabled(value: object) -> bool:
        if isinstance(value, bool):
            return value is True
        return str(value).strip().lower() in _ENABLED_VALUES
