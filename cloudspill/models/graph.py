"""ResourceGraph — DAG with typed edges.

Builds a directed graph from parsed IaCNodes by scanning attribute values
for Terraform reference patterns (e.g. ${aws_s3_bucket.name.id}) and
explicit depends_on declarations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from cloudspill.models.nodes import IaCNode


class EdgeKind(Enum):
    """Semantic relationship between two infrastructure resources."""

    ATTRIBUTE_REF = "attribute_ref"
    DEPENDS_ON = "depends_on"
    ATTACHMENT = "attachment"
    MODULE_OUTPUT = "module_output"
    SECURITY_GROUP = "security_group"


@dataclass(frozen=True)
class Edge:
    """A directed, typed edge in the resource graph."""

    source: str
    target: str
    kind: EdgeKind
    attribute: str


# Matches Terraform references like:
#   ${aws_s3_bucket.data.arn}
#   aws_s3_bucket.data.id  (without interpolation wrapper)
_REF_PATTERN = re.compile(
    r"\$\{([a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*)\.[a-zA-Z_][a-zA-Z0-9_]*\}"
)

# Bare reference without ${} — used in newer Terraform versions
_BARE_REF_PATTERN = re.compile(
    r"^([a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*)\.[a-zA-Z_][a-zA-Z0-9_]*$"
)

# Resource types that represent IAM attachments
_ATTACHMENT_TYPES = frozenset({
    "aws_iam_role_policy_attachment",
    "aws_iam_user_policy_attachment",
    "aws_iam_group_policy_attachment",
    "aws_iam_policy_attachment",
})

# Attributes that reference security groups
_SG_ATTRIBUTES = frozenset({
    "vpc_security_group_ids",
    "security_groups",
    "security_group_id",
})


class ResourceGraph:
    """Directed acyclic graph of infrastructure resources and their relationships."""

    def __init__(self) -> None:
        self._nodes: dict[str, IaCNode] = {}
        self._edges: list[Edge] = []
        self._adjacency: dict[str, list[Edge]] = {}
        self._reverse: dict[str, list[Edge]] = {}

    @classmethod
    def build(cls, nodes: list[IaCNode]) -> ResourceGraph:
        """Construct the graph from parsed nodes, detecting cross-references."""
        graph = cls()

        for node in nodes:
            graph.add_node(node)

        node_ids = set(graph._nodes.keys())

        for node in nodes:
            # Scan attributes for references to other nodes
            graph._scan_attributes(node, node.attributes, node_ids)

            # Check explicit depends_on
            depends_on = node.attributes.get("depends_on", [])
            if isinstance(depends_on, list):
                for dep in depends_on:
                    target = dep.strip('"').strip()
                    if target in node_ids:
                        graph.add_edge(Edge(
                            source=node.node_id,
                            target=target,
                            kind=EdgeKind.DEPENDS_ON,
                            attribute="depends_on",
                        ))

            # Scan children too
            for child in node.children:
                graph._scan_attributes(node, child.attributes, node_ids)

        return graph

    def _scan_attributes(
        self,
        node: IaCNode,
        attributes: dict[str, Any],
        node_ids: set[str],
    ) -> None:
        """Recursively scan attribute values for references to other nodes."""
        for attr_name, value in attributes.items():
            refs = self._extract_refs(value)
            for ref in refs:
                if ref in node_ids and ref != node.node_id:
                    kind = self._classify_edge(node, attr_name)
                    self.add_edge(Edge(
                        source=node.node_id,
                        target=ref,
                        kind=kind,
                        attribute=attr_name,
                    ))

    def _extract_refs(self, value: Any) -> list[str]:
        """Pull resource references out of an attribute value."""
        refs: list[str] = []

        if isinstance(value, str):
            # Interpolated references: ${type.name.attr}
            for match in _REF_PATTERN.finditer(value):
                refs.append(match.group(1))
            # Bare references: type.name.attr
            bare = _BARE_REF_PATTERN.match(value)
            if bare:
                refs.append(bare.group(1))
        elif isinstance(value, list):
            for item in value:
                refs.extend(self._extract_refs(item))
        elif isinstance(value, dict):
            for v in value.values():
                refs.extend(self._extract_refs(v))

        return refs

    def _classify_edge(self, source_node: IaCNode, attribute: str) -> EdgeKind:
        """Determine the semantic kind of an edge based on context."""
        if source_node.resource_type in _ATTACHMENT_TYPES:
            return EdgeKind.ATTACHMENT
        if attribute in _SG_ATTRIBUTES:
            return EdgeKind.SECURITY_GROUP
        return EdgeKind.ATTRIBUTE_REF

    def add_node(self, node: IaCNode) -> None:
        """Register a node in the graph."""
        self._nodes[node.node_id] = node
        if node.node_id not in self._adjacency:
            self._adjacency[node.node_id] = []
        if node.node_id not in self._reverse:
            self._reverse[node.node_id] = []

    def add_edge(self, edge: Edge) -> None:
        """Add a directed edge. Skips duplicates."""
        for existing in self._adjacency.get(edge.source, []):
            if existing.target == edge.target and existing.attribute == edge.attribute:
                return
        self._edges.append(edge)
        self._adjacency.setdefault(edge.source, []).append(edge)
        self._reverse.setdefault(edge.target, []).append(edge)

    def outgoing(self, node_id: str) -> list[Edge]:
        """Edges where node_id is the source."""
        return list(self._adjacency.get(node_id, []))

    def incoming(self, node_id: str) -> list[Edge]:
        """Edges where node_id is the target."""
        return list(self._reverse.get(node_id, []))

    def get_node(self, node_id: str) -> IaCNode | None:
        """Look up a node by ID."""
        return self._nodes.get(node_id)

    @property
    def nodes(self) -> dict[str, IaCNode]:
        """All nodes in the graph."""
        return dict(self._nodes)

    @property
    def edges(self) -> list[Edge]:
        """All edges in the graph."""
        return list(self._edges)
