"""S3-007: Bucket policy grants a wildcard principal.

An ``Allow`` statement in a bucket policy with a wildcard principal (``"*"`` /
``{"AWS": "*"}``) and no ``Condition`` makes the bucket public — anyone can
perform the allowed S3 actions. This is the policy-side counterpart to a public
ACL and a top cause of S3 data leaks.

This rule flags a wildcard-principal Allow (with no Condition) on an
``aws_s3_bucket_policy`` or on the inline ``policy`` of an ``aws_s3_bucket``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.policy import extract_statements, is_wildcard_principal
from cloudspill.rules.base import register


@register
class S3BucketPolicyWildcard:
    """S3-007: bucket policy allows a wildcard principal."""

    rule_id = "S3-007"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in ("aws_s3_bucket_policy", "aws_s3_bucket"):
            return []

        for stmt in extract_statements(node.attributes.get("policy", "")):
            if stmt.get("Effect") != "Allow" or stmt.get("Condition"):
                continue
            if is_wildcard_principal(stmt.get("Principal")):
                return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="S3 bucket policy grants a wildcard principal",
            description=(
                'An Allow statement in the bucket policy grants Principal "*" '
                "with no Condition, making the bucket publicly accessible for the "
                "allowed actions."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Scope the policy Principal to specific account/role ARNs, or "
                "constrain the wildcard with a Condition (e.g. aws:PrincipalOrgID, "
                "aws:SourceArn)."
            ),
            tags=frozenset(
                {"s3", "bucket-policy", "wildcard-principal", "public-access", "aws"}
            ),
        )
