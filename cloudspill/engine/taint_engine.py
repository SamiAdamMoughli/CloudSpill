"""TaintEngine — BFS propagation of findings through the resource graph.

For each finding, walks the DAG in both directions to trace how a
misconfiguration at one resource affects resources that reference it
(forward propagation) or resources it depends on (backward context).
"""

from __future__ import annotations

from collections import deque

from cloudspill.models.findings import Finding
from cloudspill.models.graph import Edge, EdgeKind, ResourceGraph
from cloudspill.models.taint import TaintPath, TaintResult


class TaintEngine:
    """Propagates findings through the DAG via BFS, producing TaintResults."""

    def __init__(self, graph: ResourceGraph) -> None:
        self._graph = graph

    def propagate(self, findings: list[Finding]) -> list[TaintResult]:
        """Trace all findings through the graph. Returns one TaintResult per finding that has downstream impact."""
        results: list[TaintResult] = []

        for finding in findings:
            paths = self._bfs_forward(finding)
            if paths:
                results.append(TaintResult(
                    finding=finding,
                    paths=tuple(paths),
                ))

        return results

    def _bfs_forward(self, finding: Finding) -> list[TaintPath]:
        """BFS from the finding's resource through incoming edges (resources that reference it).

        If resource A has a misconfiguration, and resource B references A,
        then B inherits taint from A. We walk incoming edges because in
        Terraform's reference model, the *referencing* resource points at
        the *referenced* resource — so taint flows from target to source.
        """
        source_id = finding.resource
        if self._graph.get_node(source_id) is None:
            return []

        paths: list[TaintPath] = []
        visited: set[str] = {source_id}
        queue: deque[tuple[list[str], list[EdgeKind]]] = deque()

        # Seed: find all resources that reference the tainted resource
        for edge in self._graph.incoming(source_id):
            if edge.source not in visited:
                visited.add(edge.source)
                path_nodes = [source_id, edge.source]
                path_edges = [edge.kind]
                queue.append((path_nodes, path_edges))

        while queue:
            current_path, current_edges = queue.popleft()
            current_node = current_path[-1]

            # Record this path
            paths.append(TaintPath(
                nodes=tuple(current_path),
                edges=tuple(current_edges),
                risk=self._describe_risk(finding, current_path),
            ))

            # Continue BFS: find resources that reference the current node
            for edge in self._graph.incoming(current_node):
                if edge.source not in visited:
                    visited.add(edge.source)
                    queue.append((
                        [*current_path, edge.source],
                        [*current_edges, edge.kind],
                    ))

        return paths

    def _describe_risk(self, finding: Finding, path: list[str]) -> str:
        """Generate a human-readable risk description for a taint path."""
        source = path[0]
        sink = path[-1]
        hops = len(path) - 1

        source_node = self._graph.get_node(source)
        sink_node = self._graph.get_node(sink)

        source_type = source_node.resource_type if source_node else source
        sink_type = sink_node.resource_type if sink_node else sink

        if hops == 1:
            return (
                f"{finding.title} on {source_type} propagates directly to "
                f"{sink_type} ({sink}) via reference."
            )
        return (
            f"{finding.title} on {source_type} propagates through "
            f"{hops} hops to {sink_type} ({sink})."
        )
