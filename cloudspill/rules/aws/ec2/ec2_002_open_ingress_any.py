"""EC2-002: Security group allows internet-wide ingress on a non-SSH port.

A broader companion to EC2-001: any ingress entry that allows ``0.0.0.0/0`` (or
``::/0``) exposes the targeted ports to the whole internet. Databases, admin
panels, RDP, and all-ports rules are common high-impact cases.

To avoid double-reporting, an entry that is *exactly* SSH-only (from_port 22 to
to_port 22) is left to EC2-001; everything else open to the world is flagged
here. The same shared ingress extractor as EC2-001 is used so both rules see
inline blocks and standalone ingress-rule resources identically.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.ec2.ec2_001_ssh_open import (
    _SG_TYPES,
    ingress_entries,
    is_open,
)
from cloudspill.rules.base import register


@register
class EC2OpenIngress:
    """EC2-002: ingress allows 0.0.0.0/0 on a non-SSH port."""

    rule_id = "EC2-002"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _SG_TYPES:
            return []

        for entry in ingress_entries(node):
            if not is_open(entry):
                continue
            # Exact SSH-only rule is EC2-001's job; don't double-report.
            if entry["from_port"] == 22 and entry["to_port"] == 22:
                continue
            return [self._finding(node, entry)]
        return []

    def _finding(self, node: IaCNode, entry: dict[str, object]) -> Finding:
        fp, tp = entry["from_port"], entry["to_port"]
        port_desc = (
            "all ports" if fp in (None, 0) and tp in (None, 0) else f"ports {fp}-{tp}"
        )
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Security group allows internet-wide ingress",
            description=(
                f"A security group ingress entry allows 0.0.0.0/0 (or ::/0) on "
                f"{port_desc}. The targeted services are exposed to the entire "
                "internet."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Scope the ingress CIDR to the specific networks that need "
                "access, and narrow the port range to only the required ports."
            ),
            tags=frozenset(
                {"ec2", "security-group", "ingress", "public-access", "aws"}
            ),
        )
