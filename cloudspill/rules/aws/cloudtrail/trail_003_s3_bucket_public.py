"""TRAIL-003: CloudTrail log bucket is publicly readable via a canned ACL.

CloudTrail delivers its log files to the S3 bucket named in ``s3_bucket_name``.
That bucket holds a full audit record of API activity, so it must never be
public — a public log bucket lets anyone enumerate and download the account's
audit trail, and a public-read-write bucket additionally lets them tamper with
or delete the evidence.

This rule resolves the trail's log bucket through the resource graph and flags
it when a *public* canned ACL is applied, either:

* inline on the ``aws_s3_bucket`` via its ``acl`` argument, or
* through a separate ``aws_s3_bucket_acl`` resource targeting that bucket.

Public ACLs are ``public-read`` and ``public-read-write``. The rule fires on
the trail (the resource that gives the bucket its audit-log significance); it
stays silent when the bucket cannot be resolved from the configuration — a
remote or string-only bucket name carries no ACL to inspect.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_PUBLIC_ACLS = frozenset({"public-read", "public-read-write"})


@register
class CloudTrailLogBucketPublic:
    """TRAIL-003: aws_cloudtrail log bucket has a public canned ACL."""

    rule_id = "TRAIL-003"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_cloudtrail":
            return []

        bucket = self._log_bucket(node, graph)
        if bucket is None or not self._is_public(bucket, graph):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="CloudTrail log bucket is publicly accessible",
                description=(
                    f"The S3 bucket '{bucket.name}' that stores this trail's logs "
                    "has a public canned ACL (public-read or public-read-write). "
                    "Anyone can read the account's audit trail, and a writable "
                    "bucket lets attackers tamper with or delete the evidence."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set the log bucket's ACL to 'private' and attach an "
                    "aws_s3_bucket_public_access_block with all four settings true "
                    "so the audit logs cannot be exposed publicly."
                ),
                tags=frozenset({"cloudtrail", "s3", "public-access", "audit", "aws"}),
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
    def _is_public(cls, bucket: IaCNode, graph: ResourceGraph) -> bool:
        """True if the bucket carries a public canned ACL, inline or split."""
        if cls._acl_value(bucket.attributes.get("acl")) in _PUBLIC_ACLS:
            return True

        # Modern split resource: aws_s3_bucket_acl referencing this bucket.
        for edge in graph.incoming(bucket.node_id):
            source = graph.get_node(edge.source)
            if (
                source is not None
                and source.resource_type == "aws_s3_bucket_acl"
                and cls._acl_value(source.attributes.get("acl")) in _PUBLIC_ACLS
            ):
                return True
        return False

    @staticmethod
    def _acl_value(value: object) -> str:
        return str(value).strip().lower() if value is not None else ""
