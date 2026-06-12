"""EC2 security rules.

| ID      | Finding                                          | Severity |
|---------|--------------------------------------------------|----------|
| EC2-001 | Security group allows 0.0.0.0/0 on port 22 (SSH) | CRITICAL |
| EC2-002 | Security group allows 0.0.0.0/0 on any port      | HIGH     |
| EC2-003 | IMDSv2 not required                              | HIGH     |
| EC2-004 | Instance has public IP                           | MEDIUM   |
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_OPEN_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


def _get_ingress_rules(node: IaCNode) -> list[dict[str, Any]]:
    """Extract ingress blocks from a security group node."""
    ingress = node.attributes.get("ingress", [])
    if isinstance(ingress, dict):
        return [ingress]
    if isinstance(ingress, list):
        return [i for i in ingress if isinstance(i, dict)]
    # Check children for ingress blocks
    return [c.attributes for c in node.children if c.resource_type == "ingress"]


@register
class EC2SSHOpen:
    """EC2-001: Security group allows 0.0.0.0/0 ingress on port 22."""

    rule_id = "EC2-001"
    severity = Severity.CRITICAL

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_security_group":
            return []

        for rule in _get_ingress_rules(node):
            cidr_blocks = rule.get("cidr_blocks", [])
            if isinstance(cidr_blocks, str):
                cidr_blocks = [cidr_blocks]
            from_port = rule.get("from_port", -1)
            to_port = rule.get("to_port", -1)

            if any(c in _OPEN_CIDRS for c in cidr_blocks):
                if (from_port == 22 and to_port == 22) or (
                    from_port == 0 and to_port == 0
                ):
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            title="SSH open to 0.0.0.0/0",
                            description="Security group allows SSH (port 22) from any IP address.",
                            resource=node.node_id,
                            file=node.source_file,
                            line=node.line,
                        )
                    ]
        return []


@register
class EC2OpenIngress:
    """EC2-002: Security group allows 0.0.0.0/0 ingress on any port."""

    rule_id = "EC2-002"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_security_group":
            return []

        for rule in _get_ingress_rules(node):
            cidr_blocks = rule.get("cidr_blocks", [])
            if isinstance(cidr_blocks, str):
                cidr_blocks = [cidr_blocks]
            from_port = rule.get("from_port", -1)
            to_port = rule.get("to_port", -1)

            if any(c in _OPEN_CIDRS for c in cidr_blocks):
                # Skip if already caught by EC2-001 (SSH-specific)
                if from_port == 22 and to_port == 22:
                    continue
                return [
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title="Ingress open to 0.0.0.0/0",
                        description=f"Security group allows ingress from any IP on ports {from_port}-{to_port}.",
                        resource=node.node_id,
                        file=node.source_file,
                        line=node.line,
                    )
                ]
        return []


@register
class EC2NoIMDSv2:
    """EC2-003: IMDSv2 not required."""

    rule_id = "EC2-003"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_instance":
            return []

        # hcl2 represents a singleton block as either a dict or a [dict].
        metadata = node.attributes.get("metadata_options", {})
        for block in metadata if isinstance(metadata, list) else [metadata]:
            if isinstance(block, dict) and block.get("http_tokens") == "required":
                return []
        # Also check children
        for child in node.children:
            if child.resource_type == "metadata_options":
                if child.attributes.get("http_tokens") == "required":
                    return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="IMDSv2 not required",
                description="Instance metadata service v2 is not enforced. Vulnerable to SSRF-based credential theft.",
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
            )
        ]


@register
class EC2PublicIP:
    """EC2-004: Instance has public IP."""

    rule_id = "EC2-004"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_instance":
            return []

        if node.attributes.get("associate_public_ip_address") is True:
            return [
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title="Instance has public IP",
                    description="Instance is configured with a public IP address, increasing attack surface.",
                    resource=node.node_id,
                    file=node.source_file,
                    line=node.line,
                )
            ]
        return []
