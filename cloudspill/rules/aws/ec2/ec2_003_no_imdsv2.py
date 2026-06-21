"""EC2-003: Instance metadata service does not require IMDSv2.

IMDSv1 answers metadata requests (including the instance role's temporary
credentials) to anyone who can make an HTTP GET to 169.254.169.254. A
server-side request forgery (SSRF) bug in an app on the instance is then enough
to steal those credentials. IMDSv2 closes this by requiring a signed,
PUT-issued session token — set via ``metadata_options { http_tokens =
"required" }``.

This rule flags an ``aws_instance`` or ``aws_launch_template`` whose
metadata_options does not set ``http_tokens = "required"``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register

_TARGET_TYPES = frozenset({"aws_instance", "aws_launch_template"})


@register
class EC2NoIMDSv2:
    """EC2-003: http_tokens is not 'required' in metadata_options."""

    rule_id = "EC2-003"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _TARGET_TYPES:
            return []

        if self._imdsv2_required(node):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="IMDSv2 is not required (instance metadata is exploitable via SSRF)",
                description=(
                    'metadata_options does not set http_tokens = "required", so '
                    "IMDSv1 remains enabled. An SSRF flaw in any app on the "
                    "instance can read the instance role's temporary credentials "
                    "from the metadata endpoint."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    'Set metadata_options { http_tokens = "required" } (and '
                    'http_endpoint = "enabled") to enforce IMDSv2 session tokens.'
                ),
                tags=frozenset({"ec2", "imdsv2", "ssrf", "credential-theft", "aws"}),
            )
        ]

    @staticmethod
    def _imdsv2_required(node: IaCNode) -> bool:
        blocks = as_blocks(node.attributes.get("metadata_options"))
        blocks += [
            c.attributes for c in node.children if c.resource_type == "metadata_options"
        ]
        return any(
            str(b.get("http_tokens", "")).strip().lower() == "required" for b in blocks
        )
