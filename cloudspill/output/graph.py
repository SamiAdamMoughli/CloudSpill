"""MermaidGraphFormatter — renders a ResourceGraph + findings + taint as Mermaid."""

from __future__ import annotations

import re

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import EdgeKind, ResourceGraph
from cloudspill.models.taint import TaintResult

# ── Severity → Mermaid CSS class name ────────────────────────────────────────
_SEV_CLASS: dict[Severity, str] = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}

# ── EdgeKind → label shown on the arrow ──────────────────────────────────────
_EDGE_LABEL: dict[EdgeKind, str] = {
    EdgeKind.ATTRIBUTE_REF: "ref",
    EdgeKind.DEPENDS_ON: "depends_on",
    EdgeKind.ATTACHMENT: "attached",
    EdgeKind.SECURITY_GROUP: "sg",
    EdgeKind.MODULE_OUTPUT: "output",
}

_TAINT_LABEL = "taint"

# ── Resource-type → readable short label ─────────────────────────────────────
_TYPE_ABBREV: dict[str, str] = {
    # AWS
    "aws_s3_bucket": "S3",
    "aws_s3_bucket_public_access_block": "S3 PublicBlock",
    "aws_iam_role": "IAM Role",
    "aws_iam_policy": "IAM Policy",
    "aws_iam_role_policy_attachment": "IAM Attach",
    "aws_iam_role_policy": "IAM Inline",
    "aws_instance": "EC2",
    "aws_security_group": "Sec Group",
    "aws_db_instance": "RDS",
    "aws_rds_cluster": "RDS Cluster",
    "aws_lambda_function": "Lambda",
    # Azure
    "azurerm_storage_account": "Storage Acct",
    "azurerm_storage_container": "Blob Container",
    "azurerm_network_security_group": "NSG",
    "azurerm_linux_virtual_machine": "Linux VM",
    "azurerm_public_ip": "Public IP",
    "azurerm_postgresql_server": "PostgreSQL",
    "azurerm_postgresql_firewall_rule": "PG Firewall",
    "azurerm_role_assignment": "Role Assign",
    "azurerm_linux_function_app": "Function App",
    # Docker
    "FROM": "FROM",
    "RUN": "RUN",
    "ENV": "ENV",
    "USER": "USER",
    "COPY": "COPY",
    "ADD": "ADD",
    "EXPOSE": "EXPOSE",
}


def _safe_id(node_id: str) -> str:
    """Convert a node_id to a Mermaid-safe identifier (no dots, spaces, or special chars)."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", node_id)


def _node_label(node_id: str, resource_type: str) -> str:
    """Short human-readable label for a node box."""
    name = node_id.split(".")[-1]
    type_label = _TYPE_ABBREV.get(resource_type, resource_type.split("_", 1)[-1])
    return f"{name}\\n{type_label}"


def _severity_icon(severity: Severity) -> str:
    icons = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
        Severity.INFO: "⚪",
    }
    return icons[severity]


class MermaidGraphFormatter:
    """Converts a ResourceGraph, findings, and taint results into a Mermaid diagram.

    Output: a ``flowchart LR`` diagram where:
    - Every resource is a node styled by its highest-severity finding (if any)
    - Normal graph edges are shown in grey
    - Taint propagation paths are overlaid in red
    - A legend maps severity colours and edge types
    """

    def format(
        self,
        graph: ResourceGraph,
        findings: list[Finding],
        taint_results: list[TaintResult],
    ) -> str:
        lines: list[str] = ["flowchart LR", ""]

        # ── Per-node highest severity ─────────────────────────────────────
        node_severity: dict[str, Severity] = {}
        for f in findings:
            current = node_severity.get(f.resource)
            if current is None or list(Severity).index(f.severity) < list(Severity).index(current):
                node_severity[f.resource] = f.severity

        # ── Node declarations ─────────────────────────────────────────────
        lines.append("    %% ── Nodes ───────────────────────────────────────────")
        for node_id, node in sorted(graph.nodes.items()):
            sid = _safe_id(node_id)
            label = _node_label(node_id, node.resource_type)
            sev = node_severity.get(node_id)
            if sev:
                icon = _severity_icon(sev)
                lines.append(f'    {sid}["{icon} {label}"]')
                lines.append(f"    class {sid} {_SEV_CLASS[sev]}")
            else:
                lines.append(f'    {sid}["{label}"]')
        lines.append("")

        # ── Normal graph edges ─────────────────────────────────────────────
        lines.append("    %% ── Graph edges ────────────────────────────────────")
        taint_pairs = self._taint_pairs(taint_results)
        for edge in graph.edges:
            src = _safe_id(edge.source)
            tgt = _safe_id(edge.target)
            pair = (edge.source, edge.target)
            if pair in taint_pairs:
                continue  # will be drawn as taint edge below
            label = _EDGE_LABEL.get(edge.kind, edge.kind.value)
            lines.append(f"    {src} -->|{label}| {tgt}")
        lines.append("")

        # ── Taint edges ────────────────────────────────────────────────────
        if taint_results:
            lines.append("    %% ── Taint propagation ─────────────────────────────")
            drawn: set[tuple[str, str]] = set()
            for tr in taint_results:
                for path in tr.paths:
                    nodes_seq = list(path.nodes)
                    for i in range(len(nodes_seq) - 1):
                        pair = (nodes_seq[i], nodes_seq[i + 1])
                        if pair not in drawn:
                            drawn.add(pair)
                            src = _safe_id(nodes_seq[i])
                            tgt = _safe_id(nodes_seq[i + 1])
                            lines.append(
                                f"    {src} ==|{_TAINT_LABEL}|==> {tgt}"
                            )
            lines.append("")

        # ── Finding annotations as notes ──────────────────────────────────
        if findings:
            lines.append("    %% ── Findings ────────────────────────────────────")
            for f in findings:
                fid = _safe_id(f"finding_{f.rule_id}_{f.resource}")
                sid = _safe_id(f.resource)
                icon = _severity_icon(f.severity)
                short_title = f.title[:40] + "…" if len(f.title) > 40 else f.title
                label = f"{icon} {f.rule_id}\\n{short_title}"
                lines.append(f'    {fid}{{"{label}"}}')
                lines.append(f"    class {fid} {_SEV_CLASS[f.severity]}")
                lines.append(f"    {sid} -.-> {fid}")
            lines.append("")

        # ── Style classes ──────────────────────────────────────────────────
        lines.extend([
            "    %% ── Styles ──────────────────────────────────────────────",
            "    classDef critical fill:#7f1d1d,stroke:#ef4444,color:#fecaca",
            "    classDef high    fill:#78350f,stroke:#f97316,color:#fed7aa",
            "    classDef medium  fill:#713f12,stroke:#eab308,color:#fef08a",
            "    classDef low     fill:#1e3a5f,stroke:#3b82f6,color:#bfdbfe",
            "    classDef info    fill:#1e293b,stroke:#94a3b8,color:#e2e8f0",
            "    linkStyle default stroke:#475569,stroke-width:1.5px",
        ])

        return "\n".join(lines) + "\n"

    @staticmethod
    def _taint_pairs(taint_results: list[TaintResult]) -> set[tuple[str, str]]:
        """Return all (source, target) pairs that appear on any taint path."""
        pairs: set[tuple[str, str]] = set()
        for tr in taint_results:
            for path in tr.paths:
                nodes_seq = list(path.nodes)
                for i in range(len(nodes_seq) - 1):
                    pairs.add((nodes_seq[i], nodes_seq[i + 1]))
        return pairs

    def format_summary(
        self,
        graph: ResourceGraph,
        findings: list[Finding],
        taint_results: list[TaintResult],
    ) -> str:
        """Return a plain-text summary alongside the diagram."""
        total_nodes = len(graph.nodes)
        total_edges = len(graph.edges)
        taint_paths = sum(len(tr.paths) for tr in taint_results)

        by_sev: dict[Severity, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

        sev_line = "  ".join(
            f"{_severity_icon(s)} {s.value}: {by_sev[s]}"
            for s in Severity
            if s in by_sev
        )

        return (
            f"Graph: {total_nodes} nodes, {total_edges} edges"
            + (f", {taint_paths} taint paths" if taint_paths else "")
            + (f"\nFindings: {sev_line}" if findings else "")
        )
