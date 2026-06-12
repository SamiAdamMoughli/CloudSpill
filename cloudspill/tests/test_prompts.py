"""Tests for PromptLoader — template loading, interpolation, and fallback."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from cloudspill.enrichers.ai import AIEnricher, _build_prompt
from cloudspill.enrichers.prompts import PromptLoader, VALID_MODES, _FALLBACK
from cloudspill.enrichers.types import EnrichedFinding
from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.taint import TaintPath, TaintResult
from cloudspill.models.graph import EdgeKind


def _make_finding(
    rule_id: str = "S3-001",
    severity: Severity = Severity.CRITICAL,
    tags: frozenset[str] = frozenset({"s3", "public-access"}),
    remediation: str | None = "Set acl = private.",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title="Bucket publicly readable",
        description="ACL is set to public-read.",
        resource="aws_s3_bucket.test",
        file="test.tf",
        line=42,
        tags=tags,
        remediation=remediation,
    )


# ── VALID_MODES ──────────────────────────────────────────────────────────────


class TestValidModes:
    def test_contains_explain(self) -> None:
        assert "explain" in VALID_MODES

    def test_contains_fix(self) -> None:
        assert "fix" in VALID_MODES

    def test_contains_triage(self) -> None:
        assert "triage" in VALID_MODES

    def test_is_frozenset(self) -> None:
        assert isinstance(VALID_MODES, frozenset)


# ── PromptLoader.load ────────────────────────────────────────────────────────


class TestPromptLoaderLoad:
    def setup_method(self) -> None:
        PromptLoader.clear_cache()

    def test_load_explain_returns_string(self) -> None:
        result = PromptLoader.load("explain")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_load_fix_returns_string(self) -> None:
        result = PromptLoader.load("fix")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_load_triage_returns_string(self) -> None:
        result = PromptLoader.load("triage")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_unknown_mode_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown prompt mode"):
            PromptLoader.load("summarise")

    def test_missing_file_falls_back_to_default(self) -> None:
        # Simulate a missing file by pointing the loader at a temp dir
        with patch(
            "cloudspill.enrichers.prompts._PROMPTS_DIR",
            Path("/nonexistent/path"),
        ):
            PromptLoader.clear_cache()
            result = PromptLoader.load("explain")
        assert result == _FALLBACK
        PromptLoader.clear_cache()

    def test_result_is_cached_after_first_load(self) -> None:
        PromptLoader.load("explain")
        assert PromptLoader.is_cached("explain")

    def test_cached_result_identical_on_second_call(self) -> None:
        first = PromptLoader.load("explain")
        second = PromptLoader.load("explain")
        assert first is second  # same object, not just equal

    def test_clear_cache_removes_entry(self) -> None:
        PromptLoader.load("explain")
        assert PromptLoader.is_cached("explain")
        PromptLoader.clear_cache()
        assert not PromptLoader.is_cached("explain")


# ── PromptLoader.render ──────────────────────────────────────────────────────


class TestPromptLoaderRender:
    def setup_method(self) -> None:
        PromptLoader.clear_cache()

    def test_render_interpolates_rule_id(self) -> None:
        result = PromptLoader.render("explain", rule_id="AZ-NSG-001", severity="CRITICAL", resource="res")
        assert "AZ-NSG-001" in result

    def test_render_interpolates_severity(self) -> None:
        result = PromptLoader.render("explain", rule_id="S3-001", severity="HIGH", resource="res")
        assert "HIGH" in result

    def test_render_interpolates_resource(self) -> None:
        result = PromptLoader.render("explain", rule_id="S3-001", severity="CRITICAL", resource="aws_s3_bucket.my_bucket")
        assert "aws_s3_bucket.my_bucket" in result

    def test_render_unknown_placeholder_left_unchanged(self, tmp_path: Path) -> None:
        (tmp_path / "default").mkdir()
        (tmp_path / "default" / "explain.txt").write_text(
            "rule={rule_id} unknown={unknown_field}", encoding="utf-8"
        )
        with patch("cloudspill.enrichers.prompts._PROMPTS_DIR", tmp_path):
            PromptLoader.clear_cache()
            result = PromptLoader.render("explain", rule_id="S3-001")
        assert "{unknown_field}" in result
        assert "S3-001" in result
        PromptLoader.clear_cache()

    def test_render_extra_kwargs_ignored(self) -> None:
        result = PromptLoader.render(
            "explain",
            rule_id="S3-001",
            severity="CRITICAL",
            resource="res",
            this_field_does_not_exist_in_template="whatever",
        )
        assert isinstance(result, str)

    def test_render_all_modes_succeed(self) -> None:
        fields = dict(rule_id="X-001", severity="HIGH", resource="r")
        for mode in VALID_MODES:
            result = PromptLoader.render(mode, **fields)
            assert isinstance(result, str) and len(result) > 0


# ── Template content ─────────────────────────────────────────────────────────


class TestTemplateContent:
    def setup_method(self) -> None:
        PromptLoader.clear_cache()

    def test_explain_mentions_security_expert(self) -> None:
        text = PromptLoader.load("explain")
        assert "security" in text.lower()

    def test_explain_requests_json_output(self) -> None:
        text = PromptLoader.load("explain")
        assert "json" in text.lower() or "{" in text

    def test_explain_mentions_explanation_key(self) -> None:
        text = PromptLoader.load("explain")
        assert "explanation" in text.lower()

    def test_explain_mentions_fix_key(self) -> None:
        text = PromptLoader.load("explain")
        assert "fix" in text.lower()

    def test_explain_mentions_confidence_key(self) -> None:
        text = PromptLoader.load("explain")
        assert "confidence" in text.lower()

    def test_fix_mentions_remediation(self) -> None:
        text = PromptLoader.load("fix")
        assert any(w in text.lower() for w in ("remediat", "fix", "snippet", "patch"))

    def test_triage_mentions_false_positive(self) -> None:
        text = PromptLoader.load("triage")
        assert "false positive" in text.lower() or "false-positive" in text.lower()

    def test_all_templates_contain_rule_id_placeholder(self) -> None:
        for mode in VALID_MODES:
            text = PromptLoader.load(mode)
            assert "{rule_id}" in text, f"{mode}.txt missing {{rule_id}} placeholder"

    def test_all_templates_contain_severity_placeholder(self) -> None:
        for mode in VALID_MODES:
            text = PromptLoader.load(mode)
            assert "{severity}" in text, f"{mode}.txt missing {{severity}} placeholder"


# ── Custom template directory ────────────────────────────────────────────────


class TestCustomTemplateDirectory:
    def setup_method(self) -> None:
        PromptLoader.clear_cache()

    def test_loads_custom_template(self, tmp_path: Path) -> None:
        (tmp_path / "default").mkdir()
        (tmp_path / "default" / "explain.txt").write_text(
            "Custom system prompt for {rule_id} at {severity}.", encoding="utf-8"
        )
        with patch("cloudspill.enrichers.prompts._PROMPTS_DIR", tmp_path):
            PromptLoader.clear_cache()
            result = PromptLoader.render("explain", rule_id="EC2-001", severity="HIGH")
        assert "Custom system prompt" in result
        assert "EC2-001" in result
        PromptLoader.clear_cache()

    def test_missing_template_uses_fallback(self, tmp_path: Path) -> None:
        # tmp_path has no .txt files
        with patch("cloudspill.enrichers.prompts._PROMPTS_DIR", tmp_path):
            PromptLoader.clear_cache()
            result = PromptLoader.load("fix")
        assert result == _FALLBACK
        PromptLoader.clear_cache()


# ── Fallback content ─────────────────────────────────────────────────────────


class TestFallback:
    def test_fallback_is_non_empty(self) -> None:
        assert len(_FALLBACK) > 0

    def test_fallback_requests_json(self) -> None:
        assert "json" in _FALLBACK.lower() or "JSON" in _FALLBACK


# ── AIEnricher mode integration ──────────────────────────────────────────────


class TestAIEnricherMode:
    def setup_method(self) -> None:
        PromptLoader.clear_cache()

    def test_default_mode_is_explain(self) -> None:
        enricher = AIEnricher()
        assert enricher.mode == "explain"

    def test_fix_mode_accepted(self) -> None:
        enricher = AIEnricher(mode="fix")
        assert enricher.mode == "fix"

    def test_triage_mode_accepted(self) -> None:
        enricher = AIEnricher(mode="triage")
        assert enricher.mode == "triage"

    def test_unknown_mode_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown mode"):
            AIEnricher(mode="summarise")

    def test_system_prompt_changes_with_mode(self) -> None:
        """Different modes must produce different system prompts."""
        explain_system: list[str] = []
        fix_system: list[str] = []

        def _capture_explain(system: str, user: str) -> str:
            explain_system.append(system)
            raise RuntimeError("abort")

        def _capture_fix(system: str, user: str) -> str:
            fix_system.append(system)
            raise RuntimeError("abort")

        from unittest.mock import MagicMock

        mock_explain = MagicMock(complete=_capture_explain)
        mock_fix = MagicMock(complete=_capture_fix)

        AIEnricher(mode="explain", provider=mock_explain).enrich(
            [_make_finding()], [], ResourceGraph()
        )
        AIEnricher(mode="fix", provider=mock_fix).enrich(
            [_make_finding()], [], ResourceGraph()
        )

        assert explain_system and fix_system
        assert explain_system[0] != fix_system[0]

    def test_finding_fields_interpolated_into_system_prompt(self) -> None:
        """Verify rule_id and severity appear in the rendered system prompt."""
        captured: list[str] = []

        def _capture(system: str, user: str) -> str:
            captured.append(system)
            raise RuntimeError("abort")

        from unittest.mock import MagicMock

        mock = MagicMock(complete=_capture)
        AIEnricher(mode="explain", provider=mock).enrich(
            [_make_finding(rule_id="AZ-DB-003", severity=Severity.CRITICAL)],
            [],
            ResourceGraph(),
        )

        assert captured
        assert "AZ-DB-003" in captured[0]
        assert "CRITICAL" in captured[0]

    def test_user_prompt_contains_finding_details(self) -> None:
        """_build_prompt still puts the full detail in the user message."""
        captured_user: list[str] = []

        def _capture(system: str, user: str) -> str:
            captured_user.append(user)
            raise RuntimeError("abort")

        from unittest.mock import MagicMock

        mock = MagicMock(complete=_capture)
        AIEnricher(provider=mock).enrich([_make_finding()], [], ResourceGraph())

        assert captured_user
        assert "S3-001" in captured_user[0]
        assert "aws_s3_bucket.test" in captured_user[0]


# ── _build_prompt (unchanged public API) ────────────────────────────────────


class TestBuildPromptAPI:
    """Ensure the module-level _build_prompt function still works as before."""

    def test_contains_rule_id(self) -> None:
        result = _build_prompt(_make_finding(), None, "src")
        assert "S3-001" in result

    def test_contains_severity(self) -> None:
        result = _build_prompt(_make_finding(), None, "src")
        assert "CRITICAL" in result

    def test_contains_source_context(self) -> None:
        result = _build_prompt(_make_finding(), None, "my source code here")
        assert "my source code here" in result

    def test_no_taint_message(self) -> None:
        result = _build_prompt(_make_finding(), None, "src")
        assert "No downstream propagation" in result

    def test_with_taint_includes_chain(self) -> None:
        finding = _make_finding()
        taint = TaintResult(
            finding=finding,
            paths=(
                TaintPath(
                    nodes=("aws_s3_bucket.test", "aws_lambda_function.fn"),
                    edges=(EdgeKind.ATTRIBUTE_REF,),
                    risk="data exfil risk",
                ),
            ),
        )
        result = _build_prompt(finding, taint, "src")
        assert "aws_lambda_function.fn" in result
        assert "attribute_ref" in result
