"""VPC-003: Network ACL allows all-protocol ingress from the internet.

A network ACL is the subnet-level, stateless packet filter. An ``allow`` ingress
entry from ``0.0.0.0/0`` with protocol ``-1`` (all protocols / all ports) removes
the NACL as any kind of boundary — it permits every inbound packet to the whole
subnet, leaving only security groups in the way. NACLs should at least deny
obviously unwanted ranges and protocols.

This rule flags an ``aws_network_acl_rule`` (or an inline ``ingress`` block on
``aws_network_acl``) that allows protocol ``-1`` from ``0.0.0.0/0``.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register

_OPEN_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


def _is_wildcard_allow(entry: dict[str, Any], *, egress: bool | None) -> bool:
    if egress is not None and bool(entry.get("egress")) != egress:
        return False
    if str(entry.get("rule_action", entry.get("action", ""))).strip().lower() != "allow":
        return False
    if str(entry.get("protocol", "")).strip() not in ("-1", "all"):
        return False
    cidr = str(entry.get("cidr_block", "")).strip()
    return cidr in _OPEN_CIDRS


@register
class VPCNaclWildcardIngress:
    """VPC-003: NACL allows all-protocol ingress from 0.0.0.0/0."""

    rule_id = "VPC-003"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type == "aws_network_acl_rule":
            if _is_wildcard_allow(node.attributes, egress=False):
                return [self._finding(node)]
            return []

        if node.resource_type == "aws_network_acl":
            for block in as_blocks(node.attributes.get("ingress")):
                # inline ingress blocks have no `egress` key; they are ingress.
                if _is_wildcard_allow(block, egress=None):
                    return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Network ACL allows all-protocol ingress from the internet",
            description=(
                "A NACL allow rule permits protocol -1 (all) from 0.0.0.0/0 inbound "
                "to the subnet, so the network ACL imposes no boundary and every "
                "inbound packet is allowed."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Restrict the NACL ingress to the protocols, ports, and source "
                "CIDRs the subnet actually needs; deny everything else."
            ),
            tags=frozenset(
                {"vpc", "network-acl", "ingress", "public-access", "aws"}
            ),
        )
