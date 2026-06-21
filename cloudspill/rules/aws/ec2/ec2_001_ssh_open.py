"""EC2-001: Security group exposes SSH (port 22) to the whole internet.

A security group ingress entry that allows ``0.0.0.0/0`` (or ``::/0``) on port
22 puts the SSH service of every attached instance directly on the public
internet, where it is continuously scanned and brute-forced. SSH should be
reached through a bastion, VPN, or SSM Session Manager — never an open CIDR.

The check understands all three ways an ingress entry is expressed in
Terraform, so the same shared extractor backs EC2-002:

* inline ``ingress`` blocks on ``aws_security_group``,
* standalone ``aws_security_group_rule`` (``type = "ingress"``),
* the newer ``aws_vpc_security_group_ingress_rule``.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks, as_str_list
from cloudspill.rules.base import register

_OPEN_CIDRS = frozenset({"0.0.0.0/0", "::/0"})

_SG_TYPES = frozenset(
    {
        "aws_security_group",
        "aws_security_group_rule",
        "aws_vpc_security_group_ingress_rule",
    }
)


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _entry(attrs: dict[str, Any], cidr_key: str) -> dict[str, Any]:
    return {
        "from_port": _to_int(attrs.get("from_port")),
        "to_port": _to_int(attrs.get("to_port")),
        "cidrs": as_str_list(attrs.get(cidr_key)),
    }


def ingress_entries(node: IaCNode) -> list[dict[str, Any]]:
    """Normalize a node's ingress rules to {from_port, to_port, cidrs} dicts.

    Shared by EC2-001 and EC2-002. Covers inline security-group blocks and the
    two standalone ingress-rule resource types.
    """
    rt = node.resource_type
    if rt == "aws_security_group":
        blocks = as_blocks(node.attributes.get("ingress"))
        blocks += [c.attributes for c in node.children if c.resource_type == "ingress"]
        return [_entry(b, "cidr_blocks") for b in blocks]
    if rt == "aws_security_group_rule":
        if str(node.attributes.get("type", "")).strip().lower() == "ingress":
            return [_entry(node.attributes, "cidr_blocks")]
        return []
    if rt == "aws_vpc_security_group_ingress_rule":
        entry = _entry(node.attributes, "cidr_ipv4")
        entry["cidrs"] += as_str_list(node.attributes.get("cidr_ipv6"))
        return [entry]
    return []


def is_open(entry: dict[str, Any]) -> bool:
    """True if the entry allows an internet-wide CIDR."""
    return any(c.strip() in _OPEN_CIDRS for c in entry["cidrs"])


def covers_port(entry: dict[str, Any], port: int) -> bool:
    """True if the entry's port range includes `port` (or is an all-ports rule)."""
    fp, tp = entry["from_port"], entry["to_port"]
    if fp is None and tp is None:
        return True  # no range → all ports (e.g. ip_protocol "-1")
    if fp == 0 and tp == 0:
        return True  # all ports
    if fp is None or tp is None:
        return port in (fp, tp)
    return fp <= port <= tp


@register
class EC2SSHOpen:
    """EC2-001: ingress allows 0.0.0.0/0 on port 22 (SSH)."""

    rule_id = "EC2-001"
    severity = Severity.CRITICAL

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _SG_TYPES:
            return []

        for entry in ingress_entries(node):
            if is_open(entry) and covers_port(entry, 22):
                return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="SSH (port 22) is open to the entire internet",
            description=(
                "A security group ingress entry allows 0.0.0.0/0 (or ::/0) on "
                "port 22. SSH on every attached instance is exposed to internet "
                "scanning and brute-force attacks."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Restrict the SSH ingress CIDR to a bastion/VPN range, or remove "
                "it entirely and use SSM Session Manager for shell access."
            ),
            tags=frozenset(
                {"ec2", "security-group", "ssh", "public-access", "aws"}
            ),
        )
