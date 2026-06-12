"""S3 security rules.

| ID     | Finding                               | Severity |
|--------|---------------------------------------|----------|
| S3-001 | Bucket ACL set to public-read/write   | CRITICAL |
| S3-002 | block_public_acls not enabled         | HIGH     |
| S3-003 | Server-side encryption not configured | HIGH     |
| S3-004 | Access logging not enabled            | MEDIUM   |
| S3-005 | Versioning not enabled                | LOW      |
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_PUBLIC_ACLS = frozenset({"public-read", "public-read-write"})


@register
class S3PublicACL:
    """S3-001: Bucket ACL set to public-read or public-read-write."""

    rule_id = "S3-001"
    severity = Severity.CRITICAL

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_s3_bucket":
            return []
        acl = node.attributes.get("acl", "")
        if acl in _PUBLIC_ACLS:
            return [Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Bucket publicly readable",
                description=f"Bucket ACL is set to '{acl}', making contents accessible to anyone on the internet.",
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
            )]
        return []


@register
class S3BlockPublicAccess:
    """S3-002: block_public_acls not enabled on public access block."""

    rule_id = "S3-002"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_s3_bucket_public_access_block":
            return []

        flags = [
            "block_public_acls",
            "block_public_policy",
            "ignore_public_acls",
            "restrict_public_buckets",
        ]
        disabled = [f for f in flags if node.attributes.get(f) is False]

        if disabled:
            return [Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Public access block not fully enabled",
                description=f"The following public access protections are disabled: {', '.join(disabled)}.",
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
            )]
        return []


@register
class S3NoEncryption:
    """S3-003: Server-side encryption not configured."""

    rule_id = "S3-003"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_s3_bucket":
            return []

        # Check for encryption in attributes or children
        has_encryption = (
            "server_side_encryption_configuration" in node.attributes
            or any(c.resource_type == "server_side_encryption_configuration" for c in node.children)
        )
        # Also check if there's a separate aws_s3_bucket_server_side_encryption_configuration resource
        # referencing this bucket via the graph
        for edge in graph.incoming(node.node_id):
            ref_node = graph.get_node(edge.source)
            if ref_node and ref_node.resource_type == "aws_s3_bucket_server_side_encryption_configuration":
                has_encryption = True

        if not has_encryption:
            return [Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Encryption not configured",
                description="Server-side encryption is not configured on this bucket. Data at rest is unprotected.",
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
            )]
        return []


@register
class S3NoLogging:
    """S3-004: Access logging not enabled."""

    rule_id = "S3-004"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_s3_bucket":
            return []

        has_logging = (
            "logging" in node.attributes
            or any(c.resource_type == "logging" for c in node.children)
        )
        for edge in graph.incoming(node.node_id):
            ref_node = graph.get_node(edge.source)
            if ref_node and ref_node.resource_type == "aws_s3_bucket_logging":
                has_logging = True

        if not has_logging:
            return [Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Access logging not enabled",
                description="Access logging is not configured. Bucket access events are not being recorded.",
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
            )]
        return []


@register
class S3NoVersioning:
    """S3-005: Versioning not enabled."""

    rule_id = "S3-005"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_s3_bucket":
            return []

        has_versioning = (
            "versioning" in node.attributes
            or any(c.resource_type == "versioning" for c in node.children)
        )
        for edge in graph.incoming(node.node_id):
            ref_node = graph.get_node(edge.source)
            if ref_node and ref_node.resource_type == "aws_s3_bucket_versioning":
                has_versioning = True

        if not has_versioning:
            return [Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Versioning not enabled",
                description="Bucket versioning is not enabled. Deleted or overwritten objects cannot be recovered.",
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
            )]
        return []


S3_RULES = [
    S3PublicACL(),
    S3BlockPublicAccess(),
    S3NoEncryption(),
    S3NoLogging(),
    S3NoVersioning(),
]
