"""Tests for TaintEngine."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from cloudspill.engine.rule_engine import RuleEngine
from cloudspill.engine.taint_engine import TaintEngine
from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import EdgeKind, ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.models.taint import TaintPath, TaintResult
from cloudspill.parsers.terraform import TerraformParser
from cloudspill.rules import RuleRegistry

FIXTURES = Path(__file__).parent / "fixtures"


def _make_node(
    node_id: str,
    resource_type: str = "aws_test",
    attributes: dict[str, Any] | None = None,
) -> IaCNode:
    return IaCNode(
        node_id=node_id,
        node_type="resource",
        resource_type=resource_type,
        name=node_id.split(".")[-1],
        attributes=attributes or {},
        children=(),
        source_file="test.tf",
        line=1,
    )


def _make_finding(resource: str, rule_id: str = "TEST-001") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title="Test finding",
        description="Test",
        resource=resource,
        file="test.tf",
        line=1,
    )


# ─── Basic propagation ──────────────────────────────────────────────


class TestTaintBasicPropagation:
    def test_single_hop(self) -> None:
        """A → B (B references A). Finding on A should taint B."""
        a = _make_node("aws_s3_bucket.data")
        b = _make_node("aws_lambda_function.fn", attributes={
            "bucket": "${aws_s3_bucket.data.id}"
        })
        graph = ResourceGraph.build([a, b])
        finding = _make_finding("aws_s3_bucket.data")

        results = TaintEngine(graph).propagate([finding])
        assert len(results) == 1
        assert len(results[0].paths) == 1
        path = results[0].paths[0]
        assert path.nodes == ("aws_s3_bucket.data", "aws_lambda_function.fn")

    def test_multi_hop(self) -> None:
        """A ← B ← C. Finding on A taints B, then C."""
        a = _make_node("aws_s3_bucket.data")
        b = _make_node("aws_lambda_function.fn", attributes={
            "bucket": "${aws_s3_bucket.data.id}"
        })
        c = _make_node("aws_api_gateway.gw", attributes={
            "lambda": "${aws_lambda_function.fn.arn}"
        })
        graph = ResourceGraph.build([a, b, c])
        finding = _make_finding("aws_s3_bucket.data")

        results = TaintEngine(graph).propagate([finding])
        assert len(results) == 1
        # Should have 2 paths: A→B and A→B→C
        assert len(results[0].paths) == 2
        longest = max(results[0].paths, key=lambda p: len(p.nodes))
        assert longest.nodes == ("aws_s3_bucket.data", "aws_lambda_function.fn", "aws_api_gateway.gw")

    def test_no_propagation(self) -> None:
        """Isolated node — nothing references it."""
        a = _make_node("aws_s3_bucket.isolated")
        graph = ResourceGraph.build([a])
        finding = _make_finding("aws_s3_bucket.isolated")

        results = TaintEngine(graph).propagate([finding])
        assert results == []

    def test_missing_resource_skipped(self) -> None:
        """Finding references a resource not in the graph."""
        graph = ResourceGraph.build([])
        finding = _make_finding("aws_s3_bucket.ghost")

        results = TaintEngine(graph).propagate([finding])
        assert results == []


# ─── Cycle prevention ───────────────────────────────────────────────


class TestTaintCyclePrevention:
    def test_no_revisit(self) -> None:
        """BFS should not revisit nodes even if multiple paths exist."""
        a = _make_node("aws_s3_bucket.data")
        b = _make_node("aws_lambda_function.fn", attributes={
            "bucket": "${aws_s3_bucket.data.id}"
        })
        graph = ResourceGraph.build([a, b])
        finding = _make_finding("aws_s3_bucket.data")

        results = TaintEngine(graph).propagate([finding])
        all_nodes = [n for tr in results for tp in tr.paths for n in tp.nodes]
        # b should appear at most once across all paths
        assert all_nodes.count("aws_lambda_function.fn") == 1


# ─── TaintResult structure ──────────────────────────────────────────


class TestTaintResultStructure:
    @pytest.fixture()
    def result(self) -> TaintResult:
        a = _make_node("aws_s3_bucket.data")
        b = _make_node("aws_lambda_function.fn", attributes={
            "bucket": "${aws_s3_bucket.data.id}"
        })
        graph = ResourceGraph.build([a, b])
        finding = _make_finding("aws_s3_bucket.data")
        results = TaintEngine(graph).propagate([finding])
        return results[0]

    def test_finding_preserved(self, result: TaintResult) -> None:
        assert result.finding.rule_id == "TEST-001"

    def test_paths_are_tuple(self, result: TaintResult) -> None:
        assert isinstance(result.paths, tuple)

    def test_path_nodes_are_tuple(self, result: TaintResult) -> None:
        assert isinstance(result.paths[0].nodes, tuple)

    def test_path_edges_are_tuple(self, result: TaintResult) -> None:
        assert isinstance(result.paths[0].edges, tuple)

    def test_path_has_edge_kinds(self, result: TaintResult) -> None:
        assert result.paths[0].edges[0] == EdgeKind.ATTRIBUTE_REF

    def test_risk_description_present(self, result: TaintResult) -> None:
        assert len(result.paths[0].risk) > 0
        assert "propagates" in result.paths[0].risk


# ─── Multiple findings ──────────────────────────────────────────────


class TestTaintMultipleFindings:
    def test_each_finding_gets_own_result(self) -> None:
        a = _make_node("aws_s3_bucket.data")
        b = _make_node("aws_lambda_function.fn", attributes={
            "bucket": "${aws_s3_bucket.data.id}"
        })
        graph = ResourceGraph.build([a, b])
        f1 = _make_finding("aws_s3_bucket.data", "S3-001")
        f2 = _make_finding("aws_s3_bucket.data", "S3-003")

        results = TaintEngine(graph).propagate([f1, f2])
        assert len(results) == 2
        rule_ids = {r.finding.rule_id for r in results}
        assert rule_ids == {"S3-001", "S3-003"}

    def test_finding_without_propagation_excluded(self) -> None:
        a = _make_node("aws_s3_bucket.isolated")
        b = _make_node("aws_s3_bucket.connected")
        c = _make_node("aws_lambda_function.fn", attributes={
            "bucket": "${aws_s3_bucket.connected.id}"
        })
        graph = ResourceGraph.build([a, b, c])
        f1 = _make_finding("aws_s3_bucket.isolated", "S3-001")
        f2 = _make_finding("aws_s3_bucket.connected", "S3-003")

        results = TaintEngine(graph).propagate([f1, f2])
        assert len(results) == 1
        assert results[0].finding.rule_id == "S3-003"


# ─── Fixture integration ────────────────────────────────────────────


class TestTaintS3Fixture:
    @pytest.fixture()
    def taint_results(self) -> list[TaintResult]:
        nodes = TerraformParser().parse(FIXTURES / "s3_public.tf")
        graph = ResourceGraph.build(nodes)
        findings = RuleEngine(RuleRegistry(enabled={"s3"})).evaluate(nodes, graph)
        return TaintEngine(graph).propagate(findings)

    def test_has_taint_chains(self, taint_results: list[TaintResult]) -> None:
        assert len(taint_results) > 0

    def test_s3_001_propagates(self, taint_results: list[TaintResult]) -> None:
        s3_001 = next((tr for tr in taint_results if tr.finding.rule_id == "S3-001"), None)
        assert s3_001 is not None
        assert any(
            "aws_s3_bucket_public_access_block.leaky_policy" in tp.nodes
            for tp in s3_001.paths
        )


class TestTaintFullStackFixture:
    @pytest.fixture()
    def taint_results(self) -> list[TaintResult]:
        nodes = TerraformParser().parse(FIXTURES / "full_stack.tf")
        graph = ResourceGraph.build(nodes)
        findings = RuleEngine(RuleRegistry()).evaluate(nodes, graph)
        return TaintEngine(graph).propagate(findings)

    def test_s3_taint_reaches_lambda(self, taint_results: list[TaintResult]) -> None:
        s3_results = [tr for tr in taint_results if tr.finding.rule_id.startswith("S3")]
        assert any(
            "aws_lambda_function.processor" in tp.nodes
            for tr in s3_results
            for tp in tr.paths
        )

    def test_each_s3_finding_propagates(self, taint_results: list[TaintResult]) -> None:
        s3_results = [tr for tr in taint_results if tr.finding.rule_id.startswith("S3")]
        assert len(s3_results) >= 3
