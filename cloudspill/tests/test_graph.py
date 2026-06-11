"""Tests for ResourceGraph."""

from __future__ import annotations

from pathlib import Path

import pytest

from cloudspill.models.graph import Edge, EdgeKind, ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.parsers.terraform import TerraformParser

FIXTURES = Path(__file__).parent / "fixtures"


def _make_node(
    node_id: str,
    resource_type: str = "aws_test",
    attributes: dict | None = None,
    children: tuple = (),
) -> IaCNode:
    """Helper to build test nodes quickly."""
    return IaCNode(
        node_id=node_id,
        node_type="resource",
        resource_type=resource_type,
        name=node_id.split(".")[-1],
        attributes=attributes or {},
        children=children,
        source_file="test.tf",
        line=1,
    )


# ─── Building from fixture ──────────────────────────────────────────


class TestGraphFromFixture:
    @pytest.fixture()
    def graph(self) -> ResourceGraph:
        nodes = TerraformParser().parse(FIXTURES / "s3_public.tf")
        return ResourceGraph.build(nodes)

    def test_node_count(self, graph: ResourceGraph) -> None:
        assert len(graph.nodes) == 2

    def test_edge_count(self, graph: ResourceGraph) -> None:
        assert len(graph.edges) == 1

    def test_edge_source(self, graph: ResourceGraph) -> None:
        edge = graph.edges[0]
        assert edge.source == "aws_s3_bucket_public_access_block.leaky_policy"

    def test_edge_target(self, graph: ResourceGraph) -> None:
        edge = graph.edges[0]
        assert edge.target == "aws_s3_bucket.vulnerable_bucket"

    def test_edge_kind(self, graph: ResourceGraph) -> None:
        assert graph.edges[0].kind == EdgeKind.ATTRIBUTE_REF

    def test_edge_attribute(self, graph: ResourceGraph) -> None:
        assert graph.edges[0].attribute == "bucket"

    def test_outgoing(self, graph: ResourceGraph) -> None:
        out = graph.outgoing("aws_s3_bucket_public_access_block.leaky_policy")
        assert len(out) == 1
        assert out[0].target == "aws_s3_bucket.vulnerable_bucket"

    def test_incoming(self, graph: ResourceGraph) -> None:
        inc = graph.incoming("aws_s3_bucket.vulnerable_bucket")
        assert len(inc) == 1
        assert inc[0].source == "aws_s3_bucket_public_access_block.leaky_policy"

    def test_no_outgoing_from_bucket(self, graph: ResourceGraph) -> None:
        assert graph.outgoing("aws_s3_bucket.vulnerable_bucket") == []

    def test_no_incoming_to_access_block(self, graph: ResourceGraph) -> None:
        assert graph.incoming("aws_s3_bucket_public_access_block.leaky_policy") == []


# ─── Node operations ────────────────────────────────────────────────


class TestGraphNodeOps:
    def test_add_and_get_node(self) -> None:
        graph = ResourceGraph()
        node = _make_node("aws_s3_bucket.test")
        graph.add_node(node)
        assert graph.get_node("aws_s3_bucket.test") is node

    def test_get_missing_node(self) -> None:
        graph = ResourceGraph()
        assert graph.get_node("nonexistent") is None

    def test_nodes_property_returns_copy(self) -> None:
        graph = ResourceGraph()
        graph.add_node(_make_node("aws_s3_bucket.test"))
        nodes = graph.nodes
        nodes["fake"] = _make_node("fake")
        assert "fake" not in graph.nodes


# ─── Edge operations ────────────────────────────────────────────────


class TestGraphEdgeOps:
    def test_add_edge(self) -> None:
        graph = ResourceGraph()
        graph.add_node(_make_node("a.b"))
        graph.add_node(_make_node("c.d"))
        edge = Edge(source="a.b", target="c.d", kind=EdgeKind.ATTRIBUTE_REF, attribute="ref")
        graph.add_edge(edge)
        assert len(graph.edges) == 1

    def test_duplicate_edge_skipped(self) -> None:
        graph = ResourceGraph()
        graph.add_node(_make_node("a.b"))
        graph.add_node(_make_node("c.d"))
        edge = Edge(source="a.b", target="c.d", kind=EdgeKind.ATTRIBUTE_REF, attribute="ref")
        graph.add_edge(edge)
        graph.add_edge(edge)
        assert len(graph.edges) == 1

    def test_edges_property_returns_copy(self) -> None:
        graph = ResourceGraph()
        edges = graph.edges
        edges.append(Edge(source="a", target="b", kind=EdgeKind.DEPENDS_ON, attribute="x"))
        assert len(graph.edges) == 0


# ─── Reference detection ────────────────────────────────────────────


class TestGraphReferenceDetection:
    def test_interpolated_ref(self) -> None:
        a = _make_node("aws_s3_bucket.data")
        b = _make_node("aws_lambda_function.proc", attributes={
            "s3_bucket": "${aws_s3_bucket.data.arn}"
        })
        graph = ResourceGraph.build([a, b])
        assert len(graph.edges) == 1
        assert graph.edges[0].source == "aws_lambda_function.proc"
        assert graph.edges[0].target == "aws_s3_bucket.data"

    def test_bare_ref(self) -> None:
        a = _make_node("aws_s3_bucket.data")
        b = _make_node("aws_s3_bucket_policy.pol", attributes={
            "bucket": "aws_s3_bucket.data.id"
        })
        graph = ResourceGraph.build([a, b])
        assert len(graph.edges) == 1

    def test_no_self_reference(self) -> None:
        a = _make_node("aws_s3_bucket.data", attributes={
            "ref": "${aws_s3_bucket.data.arn}"
        })
        graph = ResourceGraph.build([a])
        assert len(graph.edges) == 0

    def test_ref_to_unknown_node_ignored(self) -> None:
        a = _make_node("aws_s3_bucket.data", attributes={
            "role": "${aws_iam_role.missing.arn}"
        })
        graph = ResourceGraph.build([a])
        assert len(graph.edges) == 0

    def test_multiple_refs_in_one_attribute(self) -> None:
        a = _make_node("aws_s3_bucket.one")
        b = _make_node("aws_s3_bucket.two")
        c = _make_node("aws_lambda_function.fn", attributes={
            "env": "${aws_s3_bucket.one.arn}:${aws_s3_bucket.two.arn}"
        })
        graph = ResourceGraph.build([a, b, c])
        assert len(graph.edges) == 2

    def test_ref_in_nested_list(self) -> None:
        a = _make_node("aws_security_group.sg")
        b = _make_node("aws_instance.web", attributes={
            "vpc_security_group_ids": ["${aws_security_group.sg.id}"]
        })
        graph = ResourceGraph.build([a, b])
        assert len(graph.edges) == 1
        assert graph.edges[0].kind == EdgeKind.SECURITY_GROUP

    def test_ref_in_nested_dict(self) -> None:
        a = _make_node("aws_s3_bucket.logs")
        b = _make_node("aws_s3_bucket.data", attributes={
            "logging": {"target_bucket": "${aws_s3_bucket.logs.id}"}
        })
        graph = ResourceGraph.build([a, b])
        assert len(graph.edges) == 1


# ─── Edge classification ────────────────────────────────────────────


class TestGraphEdgeClassification:
    def test_attachment_type(self) -> None:
        role = _make_node("aws_iam_role.app")
        attach = _make_node(
            "aws_iam_role_policy_attachment.attach",
            resource_type="aws_iam_role_policy_attachment",
            attributes={"role": "${aws_iam_role.app.name}"},
        )
        graph = ResourceGraph.build([role, attach])
        assert graph.edges[0].kind == EdgeKind.ATTACHMENT

    def test_security_group_type(self) -> None:
        sg = _make_node("aws_security_group.web")
        instance = _make_node("aws_instance.app", attributes={
            "vpc_security_group_ids": ["${aws_security_group.web.id}"]
        })
        graph = ResourceGraph.build([sg, instance])
        assert graph.edges[0].kind == EdgeKind.SECURITY_GROUP

    def test_default_attribute_ref(self) -> None:
        a = _make_node("aws_s3_bucket.data")
        b = _make_node("aws_lambda_function.fn", attributes={
            "s3_bucket": "${aws_s3_bucket.data.arn}"
        })
        graph = ResourceGraph.build([a, b])
        assert graph.edges[0].kind == EdgeKind.ATTRIBUTE_REF


# ─── depends_on ──────────────────────────────────────────────────────


class TestGraphDependsOn:
    def test_explicit_depends_on(self) -> None:
        a = _make_node("aws_s3_bucket.data")
        b = _make_node("aws_lambda_function.fn", attributes={
            "depends_on": ["aws_s3_bucket.data"]
        })
        graph = ResourceGraph.build([a, b])
        deps = [e for e in graph.edges if e.kind == EdgeKind.DEPENDS_ON]
        assert len(deps) == 1
        assert deps[0].target == "aws_s3_bucket.data"

    def test_depends_on_missing_target_ignored(self) -> None:
        a = _make_node("aws_lambda_function.fn", attributes={
            "depends_on": ["aws_s3_bucket.nonexistent"]
        })
        graph = ResourceGraph.build([a])
        assert len(graph.edges) == 0


# ─── Empty graph ─────────────────────────────────────────────────────


class TestGraphEmpty:
    def test_empty_build(self) -> None:
        graph = ResourceGraph.build([])
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_no_refs(self) -> None:
        a = _make_node("aws_s3_bucket.one", attributes={"bucket": "my-bucket"})
        b = _make_node("aws_s3_bucket.two", attributes={"bucket": "other-bucket"})
        graph = ResourceGraph.build([a, b])
        assert len(graph.nodes) == 2
        assert len(graph.edges) == 0
