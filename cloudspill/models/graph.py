"""ResourceGraph — DAG with typed edges."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

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
        raise NotImplementedError

    def add_node(self, node: IaCNode) -> None:
        raise NotImplementedError

    def add_edge(self, edge: Edge) -> None:
        raise NotImplementedError

    def outgoing(self, node_id: str) -> list[Edge]:
        """Edges where node_id is the source."""
        raise NotImplementedError

    def incoming(self, node_id: str) -> list[Edge]:
        """Edges where node_id is the target."""
        raise NotImplementedError

    def get_node(self, node_id: str) -> IaCNode | None:
        raise NotImplementedError

    @property
    def nodes(self) -> dict[str, IaCNode]:
        raise NotImplementedError

    @property
    def edges(self) -> list[Edge]:
        raise NotImplementedError
