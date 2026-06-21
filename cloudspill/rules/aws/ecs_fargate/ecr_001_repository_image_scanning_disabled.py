"""ECR-001: ECR repository does not scan images on push.

``aws_ecr_repository`` can scan each pushed image for known CVEs via
``image_scanning_configuration { scan_on_push = true }``. With it off,
vulnerable base images and dependencies land in the registry unnoticed and get
deployed to ECS/EKS without any signal. Scan-on-push is the cheapest place to
catch them — at the moment the image enters the registry.

This rule flags an ``aws_ecr_repository`` whose scan_on_push is not enabled.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register


def _is_true(value: object) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() == "true"


@register
class ECRImageScanningDisabled:
    """ECR-001: aws_ecr_repository has scan_on_push not enabled."""

    rule_id = "ECR-001"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_ecr_repository":
            return []

        for block in as_blocks(node.attributes.get("image_scanning_configuration")):
            if _is_true(block.get("scan_on_push")):
                return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="ECR repository does not scan images on push",
                description=(
                    "image_scanning_configuration.scan_on_push is not enabled on "
                    "this aws_ecr_repository, so pushed images are not scanned for "
                    "known vulnerabilities and can be deployed with no CVE signal."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add image_scanning_configuration { scan_on_push = true } (or "
                    "enable enhanced scanning at the registry level)."
                ),
                tags=frozenset(
                    {"ecr", "image-scanning", "vulnerability", "supply-chain", "aws"}
                ),
            )
        ]
