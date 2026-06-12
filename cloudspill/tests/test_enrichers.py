"""Tests for enrichment layer."""

from __future__ import annotations

from cloudspill.enrichers.ai import AIEnricher
from cloudspill.enrichers.base import Enricher
from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.taint import TaintResult


def _make_finding() -> Finding:
    return Finding(
        rule_id="S3-001",
        severity=Severity.CRITICAL,
        title="Test finding",
        description="Test description",
        resource="aws_s3_bucket.test",
        file="test.tf",
        line=1,
    )


class TestEnricherProtocol:
    def test_ai_enricher_satisfies_protocol(self) -> None:
        """AIEnricher must be structurally compatible with the Enricher protocol."""
        enricher = AIEnricher()
        assert hasattr(enricher, "enrich")
        assert callable(enricher.enrich)


class TestAIEnricher:
    def test_returns_list(self) -> None:
        enricher = AIEnricher()
        results = enricher.enrich([_make_finding()], [], ResourceGraph())
        assert isinstance(results, list)
        assert len(results) == 1

    def test_result_has_required_keys(self) -> None:
        enricher = AIEnricher()
        results = enricher.enrich([_make_finding()], [], ResourceGraph())
        result = results[0]
        assert "rule_id" in result
        assert "resource" in result
        assert "explanation" in result
        assert "fix" in result

    def test_graceful_without_server(self) -> None:
        """Should not raise even without a running inference server."""
        enricher = AIEnricher()
        results = enricher.enrich([_make_finding()], [], ResourceGraph())
        assert len(results) == 1
        assert "not connected" in results[0]["explanation"].lower() or len(results[0]["explanation"]) > 0

    def test_empty_findings(self) -> None:
        enricher = AIEnricher()
        results = enricher.enrich([], [], ResourceGraph())
        assert results == []

    def test_custom_model(self) -> None:
        enricher = AIEnricher(model="qwen3.6-35b-a3b")
        assert enricher.model == "qwen3.6-35b-a3b"

    def test_custom_base_url(self) -> None:
        enricher = AIEnricher(base_url="http://localhost:8000/v1")
        assert "localhost:8000" in enricher.base_url
