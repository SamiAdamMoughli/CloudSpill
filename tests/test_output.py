"""Tests for output formatters."""

from __future__ import annotations

import json

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import EdgeKind
from cloudspill.models.taint import TaintPath, TaintResult
from cloudspill.output.json import JsonFormatter
from cloudspill.output.markdown import MarkdownFormatter
from cloudspill.output.table import TableFormatter


def _make_finding(
    rule_id: str = "S3-001",
    severity: Severity = Severity.CRITICAL,
    title: str = "Test finding",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description="Test description",
        resource="aws_s3_bucket.test",
        file="infra/main.tf",
        line=10,
    )


def _make_taint(finding: Finding | None = None) -> TaintResult:
    f = finding or _make_finding()
    return TaintResult(
        finding=f,
        paths=(
            TaintPath(
                nodes=("aws_s3_bucket.test", "aws_lambda_function.fn"),
                edges=(EdgeKind.ATTRIBUTE_REF,),
                risk="Test risk propagation.",
            ),
        ),
    )


# ─── JSON Formatter ─────────────────────────────────────────────────


class TestJsonFormatter:
    def test_valid_json(self) -> None:
        output = JsonFormatter().format([_make_finding()], [])
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_findings_array(self) -> None:
        output = JsonFormatter().format(
            [_make_finding(), _make_finding("S3-003", Severity.HIGH)], []
        )
        parsed = json.loads(output)
        assert len(parsed["findings"]) == 2

    def test_finding_fields(self) -> None:
        output = JsonFormatter().format([_make_finding()], [])
        f = json.loads(output)["findings"][0]
        assert f["rule_id"] == "S3-001"
        assert f["severity"] == "CRITICAL"
        assert f["resource"] == "aws_s3_bucket.test"
        assert f["file"] == "infra/main.tf"
        assert f["line"] == 10

    def test_taint_results_included(self) -> None:
        f = _make_finding()
        output = JsonFormatter().format([f], [_make_taint(f)])
        parsed = json.loads(output)
        assert len(parsed["taint_results"]) == 1
        assert parsed["taint_results"][0]["finding"] == "S3-001"
        assert len(parsed["taint_results"][0]["paths"]) == 1

    def test_taint_path_structure(self) -> None:
        f = _make_finding()
        output = JsonFormatter().format([f], [_make_taint(f)])
        path = json.loads(output)["taint_results"][0]["paths"][0]
        assert path["nodes"] == ["aws_s3_bucket.test", "aws_lambda_function.fn"]
        assert path["edges"] == ["attribute_ref"]
        assert "risk" in path

    def test_summary(self) -> None:
        output = JsonFormatter().format([_make_finding()], [_make_taint()])
        parsed = json.loads(output)
        assert parsed["summary"]["total_findings"] == 1
        assert parsed["summary"]["taint_chains"] == 1

    def test_empty_findings(self) -> None:
        output = JsonFormatter().format([], [])
        parsed = json.loads(output)
        assert parsed["findings"] == []
        assert parsed["summary"]["total_findings"] == 0


# ─── Markdown Formatter ─────────────────────────────────────────────


class TestMarkdownFormatter:
    def test_header(self) -> None:
        output = MarkdownFormatter().format([_make_finding()], [])
        assert output.startswith("# CloudSpill")

    def test_findings_table(self) -> None:
        output = MarkdownFormatter().format([_make_finding()], [])
        assert "| S3-001 |" in output
        assert "| CRITICAL |" in output

    def test_taint_section(self) -> None:
        f = _make_finding()
        output = MarkdownFormatter().format([f], [_make_taint(f)])
        assert "## Taint Analysis" in output
        assert "`aws_s3_bucket.test`" in output
        assert "`aws_lambda_function.fn`" in output

    def test_no_taint_section_when_empty(self) -> None:
        output = MarkdownFormatter().format([_make_finding()], [])
        assert "Taint Analysis" not in output

    def test_empty_findings(self) -> None:
        output = MarkdownFormatter().format([], [])
        assert "No findings detected" in output

    def test_summary_line(self) -> None:
        output = MarkdownFormatter().format([_make_finding()], [])
        assert "**1 CRITICAL**" in output

    def test_severity_ordering(self) -> None:
        findings = [
            _make_finding("S3-005", Severity.LOW, "Low finding"),
            _make_finding("S3-001", Severity.CRITICAL, "Critical finding"),
        ]
        output = MarkdownFormatter().format(findings, [])
        crit_pos = output.index("S3-001")
        low_pos = output.index("S3-005")
        assert crit_pos < low_pos


# ─── Table Formatter ─────────────────────────────────────────────────


class TestTableFormatter:
    def test_returns_summary_string(self) -> None:
        result = TableFormatter().format([_make_finding()], [])
        assert "1 CRITICAL" in result

    def test_empty_findings_message(self) -> None:
        result = TableFormatter().format([], [])
        assert "No findings" in result

    def test_taint_count_in_summary(self) -> None:
        f = _make_finding()
        result = TableFormatter(show_taint=True).format([f], [_make_taint(f)])
        assert "1 taint chain" in result

    def test_multiple_taint_plural(self) -> None:
        f1 = _make_finding("S3-001")
        f2 = _make_finding("S3-003", Severity.HIGH)
        result = TableFormatter().format([f1, f2], [_make_taint(f1), _make_taint(f2)])
        assert "2 taint chains" in result
