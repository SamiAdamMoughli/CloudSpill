"""Tests for MermaidGraphFormatter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import Edge, EdgeKind, ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.models.taint import TaintPath, TaintResult
from cloudspill.output.graph import MermaidGraphFormatter, _safe_id


def _make_node(
    node_id: str,
    resource_type: str = "aws_s3_bucket",
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


def _make_finding(resource: str, severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id="S3-001",
        severity=severity,
        title="Bucket publicly readable",
        description="ACL is public-read.",
        resource=resource,
        file="test.tf",
        line=1,
    )


def _two_node_graph() -> tuple[ResourceGraph, IaCNode, IaCNode]:
    bucket = _make_node(
        "aws_s3_bucket.data",
        "aws_s3_bucket",
        {"lambda_arn": "${aws_lambda_function.processor.arn}"},
    )
    fn = _make_node("aws_lambda_function.processor", "aws_lambda_function", {})
    graph = ResourceGraph.build([bucket, fn])
    return graph, bucket, fn


# ── _safe_id ────────────────────────────────────────────────────────────────


class TestSafeId:
    def test_dots_replaced(self) -> None:
        assert "." not in _safe_id("aws_s3_bucket.data")

    def test_spaces_replaced(self) -> None:
        assert " " not in _safe_id("my resource name")

    def test_alphanumeric_preserved(self) -> None:
        result = _safe_id("aws_s3_bucket_data")
        assert result == "aws_s3_bucket_data"


# ── Basic structure ─────────────────────────────────────────────────────────


class TestMermaidBasicStructure:
    def test_starts_with_flowchart(self) -> None:
        graph, _, _ = _two_node_graph()
        output = MermaidGraphFormatter().format(graph, [], [])
        assert output.startswith("flowchart LR")

    def test_contains_node_ids(self) -> None:
        graph, _, _ = _two_node_graph()
        output = MermaidGraphFormatter().format(graph, [], [])
        assert "aws_s3_bucket_data" in output
        assert "aws_lambda_function_processor" in output

    def test_edge_present(self) -> None:
        graph, _, _ = _two_node_graph()
        output = MermaidGraphFormatter().format(graph, [], [])
        assert "-->" in output

    def test_empty_graph_valid(self) -> None:
        output = MermaidGraphFormatter().format(ResourceGraph(), [], [])
        assert "flowchart LR" in output

    def test_node_label_includes_name(self) -> None:
        graph, _, _ = _two_node_graph()
        output = MermaidGraphFormatter().format(graph, [], [])
        assert "data" in output
        assert "processor" in output


# ── Severity styling ────────────────────────────────────────────────────────


class TestSeverityStyling:
    def test_critical_finding_class_applied(self) -> None:
        graph, bucket, _ = _two_node_graph()
        findings = [_make_finding(bucket.node_id, Severity.CRITICAL)]
        output = MermaidGraphFormatter().format(graph, findings, [])
        assert "critical" in output

    def test_high_finding_class_applied(self) -> None:
        graph, bucket, _ = _two_node_graph()
        findings = [_make_finding(bucket.node_id, Severity.HIGH)]
        output = MermaidGraphFormatter().format(graph, findings, [])
        assert "high" in output

    def test_severity_icon_present(self) -> None:
        graph, bucket, _ = _two_node_graph()
        findings = [_make_finding(bucket.node_id, Severity.CRITICAL)]
        output = MermaidGraphFormatter().format(graph, findings, [])
        assert "🔴" in output

    def test_classDef_block_present(self) -> None:
        graph, _, _ = _two_node_graph()
        output = MermaidGraphFormatter().format(graph, [], [])
        assert "classDef critical" in output
        assert "classDef high" in output

    def test_highest_severity_wins(self) -> None:
        """Two findings on same resource: diagram shows the worse one."""
        graph, bucket, _ = _two_node_graph()
        findings = [
            _make_finding(bucket.node_id, Severity.MEDIUM),
            _make_finding(bucket.node_id, Severity.CRITICAL),
        ]
        output = MermaidGraphFormatter().format(graph, findings, [])
        assert "critical" in output
        # medium class should not appear for the same node (it's overridden)
        # The classDef line is always present but the node shouldn't be styled medium
        sid = _safe_id(bucket.node_id)
        assert f"class {sid} critical" in output


# ── Taint overlay ────────────────────────────────────────────────────────────


class TestTaintOverlay:
    def _make_taint(self, finding: Finding, src: str, dst: str) -> TaintResult:
        return TaintResult(
            finding=finding,
            paths=(
                TaintPath(
                    nodes=(src, dst),
                    edges=(EdgeKind.ATTRIBUTE_REF,),
                    risk="Misconfiguration reaches Lambda.",
                ),
            ),
        )

    def test_taint_arrow_style(self) -> None:
        graph, bucket, fn = _two_node_graph()
        finding = _make_finding(bucket.node_id)
        taint = self._make_taint(finding, bucket.node_id, fn.node_id)
        output = MermaidGraphFormatter().format(graph, [finding], [taint])
        assert "==|taint|==>" in output

    def test_taint_edge_not_duplicated_as_normal(self) -> None:
        graph, bucket, fn = _two_node_graph()
        finding = _make_finding(bucket.node_id)
        taint = self._make_taint(finding, bucket.node_id, fn.node_id)
        output = MermaidGraphFormatter().format(graph, [finding], [taint])
        src = _safe_id(bucket.node_id)
        tgt = _safe_id(fn.node_id)
        # The normal ref edge between these two must not appear separately
        normal_arrow = f"{src} -->|ref| {tgt}"
        assert normal_arrow not in output

    def test_no_taint_no_taint_section(self) -> None:
        graph, _, _ = _two_node_graph()
        output = MermaidGraphFormatter().format(graph, [], [])
        assert "==|taint|==>" not in output


# ── Finding annotation nodes ─────────────────────────────────────────────────


class TestFindingAnnotations:
    def test_finding_node_present(self) -> None:
        graph, bucket, _ = _two_node_graph()
        findings = [_make_finding(bucket.node_id)]
        output = MermaidGraphFormatter().format(graph, findings, [])
        # Finding nodes use {diamond} shape with rule_id
        assert "S3-001" in output

    def test_finding_linked_to_resource(self) -> None:
        graph, bucket, _ = _two_node_graph()
        findings = [_make_finding(bucket.node_id)]
        output = MermaidGraphFormatter().format(graph, findings, [])
        assert "-.-> " in output  # dashed arrow from resource → finding node

    def test_no_findings_no_annotations(self) -> None:
        graph, _, _ = _two_node_graph()
        output = MermaidGraphFormatter().format(graph, [], [])
        assert "-.-> " not in output


# ── Graph-file output ────────────────────────────────────────────────────────


class TestGraphFile:
    def test_writes_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "graph.mmd"
        graph, bucket, _ = _two_node_graph()
        diagram = MermaidGraphFormatter().format(graph, [], [])
        out.write_text(diagram, encoding="utf-8")
        content = out.read_text(encoding="utf-8")
        assert content.startswith("flowchart LR")

    def test_file_is_valid_utf8(self, tmp_path: Path) -> None:
        out = tmp_path / "graph.mmd"
        graph, bucket, _ = _two_node_graph()
        findings = [_make_finding(bucket.node_id, Severity.CRITICAL)]
        diagram = MermaidGraphFormatter().format(graph, findings, [])
        out.write_bytes(diagram.encode("utf-8"))
        assert out.read_text(encoding="utf-8") == diagram


# ── Summary ──────────────────────────────────────────────────────────────────


class TestFormatSummary:
    def test_node_count_present(self) -> None:
        graph, _, _ = _two_node_graph()
        summary = MermaidGraphFormatter().format_summary(graph, [], [])
        assert "2 nodes" in summary

    def test_edge_count_present(self) -> None:
        graph, _, _ = _two_node_graph()
        summary = MermaidGraphFormatter().format_summary(graph, [], [])
        assert "edges" in summary

    def test_finding_severity_in_summary(self) -> None:
        graph, bucket, _ = _two_node_graph()
        findings = [_make_finding(bucket.node_id, Severity.CRITICAL)]
        summary = MermaidGraphFormatter().format_summary(graph, findings, [])
        assert "CRITICAL" in summary

    def test_taint_paths_in_summary(self) -> None:
        graph, bucket, fn = _two_node_graph()
        finding = _make_finding(bucket.node_id)
        taint = TaintResult(
            finding=finding,
            paths=(
                TaintPath(
                    nodes=(bucket.node_id, fn.node_id),
                    edges=(EdgeKind.ATTRIBUTE_REF,),
                    risk="risk",
                ),
            ),
        )
        summary = MermaidGraphFormatter().format_summary(graph, [finding], [taint])
        assert "taint" in summary

    def test_empty_graph_summary(self) -> None:
        summary = MermaidGraphFormatter().format_summary(ResourceGraph(), [], [])
        assert "0 nodes" in summary


# ── Fixture integration (real parse → graph → diagram) ───────────────────────


class TestFixtureIntegration:
    def test_aws_fixture_produces_valid_mermaid(self) -> None:
        from cloudspill.engine.rule_engine import RuleEngine
        from cloudspill.engine.taint_engine import TaintEngine
        from cloudspill.parsers.terraform import TerraformParser
        from cloudspill.rules import RuleRegistry

        fixtures = Path(__file__).parent / "fixtures"
        nodes = TerraformParser().parse(fixtures / "s3_public.tf")
        graph = ResourceGraph.build(nodes)
        findings = RuleEngine(RuleRegistry(enabled={"s3"})).evaluate(nodes, graph)
        taint_results = TaintEngine(graph).propagate(findings)

        output = MermaidGraphFormatter().format(graph, findings, taint_results)

        assert output.startswith("flowchart LR")
        assert "aws_s3_bucket" in output or "vulnerable_bucket" in output
        assert "classDef" in output
