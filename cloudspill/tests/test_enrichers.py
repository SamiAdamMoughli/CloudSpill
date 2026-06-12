"""Tests for AI enrichment layer."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from cloudspill.enrichers.ai import (
    AIEnricher,
    _build_prompt,
    _read_source_context,
)
from cloudspill.enrichers.types import EnrichedFinding
from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import EdgeKind, ResourceGraph
from cloudspill.models.taint import TaintPath, TaintResult


def _make_finding(rule_id: str = "S3-001") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.CRITICAL,
        title="Bucket publicly readable",
        description="Bucket ACL is set to public-read.",
        resource="aws_s3_bucket.test",
        file="test.tf",
        line=1,
    )


def _make_taint(finding: Finding | None = None) -> TaintResult:
    f = finding or _make_finding()
    return TaintResult(
        finding=f,
        paths=(
            TaintPath(
                nodes=("aws_s3_bucket.test", "aws_lambda_function.fn"),
                edges=(EdgeKind.ATTRIBUTE_REF,),
                risk="Test risk.",
            ),
        ),
    )


# ─── AIEnricher ──────────────────────────────────────────────────────


class TestAIEnricherConfig:
    def test_default_model(self) -> None:
        enricher = AIEnricher()
        assert enricher.model == "qwen3.6-35b-a3b"

    def test_custom_model(self) -> None:
        enricher = AIEnricher(model="gemma4:31b-it-qat")
        assert enricher.model == "gemma4:31b-it-qat"

    def test_custom_url(self) -> None:
        enricher = AIEnricher(base_url="http://gpu-server:8000/v1")
        assert "gpu-server:8000" in enricher.base_url

    def test_url_ends_with_completions(self) -> None:
        enricher = AIEnricher(base_url="http://localhost:11434/v1/")
        assert enricher.base_url.endswith("/chat/completions")

    def test_custom_temperature(self) -> None:
        enricher = AIEnricher(temperature=0.7)
        assert enricher.temperature == 0.7


class TestAIEnricherOffline:
    """Tests that run without a model server."""

    def test_graceful_no_server(self) -> None:
        enricher = AIEnricher()
        results = enricher.enrich([_make_finding()], [], ResourceGraph())
        assert len(results) == 1
        assert isinstance(results[0], EnrichedFinding)
        assert "unavailable" in results[0].explanation.lower()

    def test_empty_findings(self) -> None:
        enricher = AIEnricher()
        assert enricher.enrich([], [], ResourceGraph()) == []

    def test_result_is_typed(self) -> None:
        enricher = AIEnricher()
        result = enricher.enrich([_make_finding()], [], ResourceGraph())[0]
        assert isinstance(result, EnrichedFinding)
        assert result.finding.rule_id == "S3-001"
        assert result.finding.resource == "aws_s3_bucket.test"
        assert isinstance(result.explanation, str)
        assert isinstance(result.remediation_patch, str)

    def test_multiple_findings(self) -> None:
        enricher = AIEnricher()
        findings = [_make_finding("S3-001"), _make_finding("S3-003")]
        results = enricher.enrich(findings, [], ResourceGraph())
        assert len(results) == 2


class TestAIEnricherWithMock:
    """Tests with mocked HTTP responses."""

    def test_successful_enrichment(self) -> None:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{
                "message": {
                    "content": (
                        '{"explanation": "The bucket is public.",'
                        ' "fix": "acl = \\"private\\""}'
                    )
                }
            }]
        }
        mock_response.raise_for_status = MagicMock()

        enricher = AIEnricher()
        with patch("httpx.Client") as mock_client:
            inner = MagicMock(post=MagicMock(return_value=mock_response))
            mock_client.return_value.__enter__ = MagicMock(return_value=inner)
            mock_client.return_value.__exit__ = MagicMock(return_value=False)

            results = enricher.enrich([_make_finding()], [], ResourceGraph())
            assert results[0].explanation == "The bucket is public."
            assert "private" in results[0].remediation_patch

    def test_strips_thinking_tags(self) -> None:
        from cloudspill.enrichers.parser import parse_llm_response
        content = (
            "<think>Let me analyze this...</think>"
            '{"explanation": "Fixed.", "fix": "done"}'
        )
        result = parse_llm_response(content)
        assert result is not None
        assert "think" not in result.get("explanation", "")
        assert result["explanation"] == "Fixed."


# ─── Prompt building ────────────────────────────────────────────────


class TestPromptBuilding:
    def test_prompt_includes_rule_id(self) -> None:
        prompt = _build_prompt(_make_finding(), None, "source code")
        assert "S3-001" in prompt

    def test_prompt_includes_severity(self) -> None:
        prompt = _build_prompt(_make_finding(), None, "source code")
        assert "CRITICAL" in prompt

    def test_prompt_includes_taint(self) -> None:
        f = _make_finding()
        prompt = _build_prompt(f, _make_taint(f), "source code")
        assert "aws_lambda_function.fn" in prompt
        assert "attribute_ref" in prompt

    def test_prompt_no_taint(self) -> None:
        prompt = _build_prompt(_make_finding(), None, "source code")
        assert "No downstream propagation" in prompt

    def test_prompt_includes_source(self) -> None:
        prompt = _build_prompt(_make_finding(), None, "bucket = public")
        assert "bucket = public" in prompt


class TestSourceContext:
    def test_reads_existing_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.tf"
        f.write_text("line1\nline2\nline3\nline4\nline5\n")
        context = _read_source_context(str(f), 3, window=1)
        assert "line2" in context
        assert "line3" in context
        assert "line4" in context

    def test_missing_file(self) -> None:
        context = _read_source_context("/nonexistent/path.tf", 1)
        assert "Could not read" in context

    def test_line_numbers_shown(self, tmp_path: Path) -> None:
        f = tmp_path / "test.tf"
        f.write_text("a\nb\nc\n")
        context = _read_source_context(str(f), 2, window=0)
        assert "2 |" in context
