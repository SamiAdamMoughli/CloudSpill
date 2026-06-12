"""Tests for enrichers/parser.py — every normalisation strategy."""

from __future__ import annotations

import json

import pytest

from cloudspill.enrichers.parser import (
    _extract_json_object,
    _repair_partial_json,
    _strip_code_fences,
    parse_llm_response,
    strip_think_tags,
)


# ── strip_think_tags ──────────────────────────────────────────────────────────


class TestStripThinkTags:
    def test_removes_single_block(self) -> None:
        result = strip_think_tags("<think>some reasoning</think>hello")
        assert result == "hello"

    def test_removes_multiple_blocks(self) -> None:
        result = strip_think_tags("<think>a</think>middle<think>b</think>end")
        assert result == "middleend"

    def test_multiline_block(self) -> None:
        result = strip_think_tags("<think>\nline1\nline2\n</think>after")
        assert "line1" not in result
        assert result == "after"

    def test_no_think_block_unchanged(self) -> None:
        text = '{"explanation": "hello"}'
        assert strip_think_tags(text) == text

    def test_strips_surrounding_whitespace(self) -> None:
        result = strip_think_tags("<think>x</think>   hello   ")
        assert result == "hello"

    def test_case_insensitive(self) -> None:
        result = strip_think_tags("<THINK>x</THINK>after")
        assert "THINK" not in result
        assert result == "after"

    def test_tag_with_attributes(self) -> None:
        result = strip_think_tags('<think class="hidden">x</think>json')
        assert result == "json"

    def test_empty_input(self) -> None:
        assert strip_think_tags("") == ""

    def test_only_think_block(self) -> None:
        assert strip_think_tags("<think>everything</think>") == ""


# ── _strip_code_fences ────────────────────────────────────────────────────────


class TestStripCodeFences:
    def test_strips_json_fence(self) -> None:
        text = '```json\n{"key": "value"}\n```'
        result = _strip_code_fences(text)
        assert result == '{"key": "value"}'

    def test_strips_plain_fence(self) -> None:
        text = '```\n{"key": "value"}\n```'
        result = _strip_code_fences(text)
        assert result == '{"key": "value"}'

    def test_strips_fence_no_language(self) -> None:
        text = "```\nhello\n```"
        assert _strip_code_fences(text) == "hello"

    def test_no_fence_unchanged(self) -> None:
        text = '{"key": "value"}'
        assert _strip_code_fences(text) == text

    def test_prose_before_and_after_fence(self) -> None:
        text = 'Here is the JSON:\n```json\n{"a": 1}\n```\nHope that helps.'
        result = _strip_code_fences(text)
        assert result == '{"a": 1}'

    def test_multiline_content_preserved(self) -> None:
        inner = '{\n  "explanation": "test",\n  "fix": ""\n}'
        text = f"```json\n{inner}\n```"
        result = _strip_code_fences(text)
        assert json.loads(result)["explanation"] == "test"


# ── _extract_json_object ──────────────────────────────────────────────────────


class TestExtractJsonObject:
    def test_extracts_from_prose_prefix(self) -> None:
        text = 'Here is the answer: {"key": "value"} — hope that helps.'
        result = _extract_json_object(text)
        assert result == '{"key": "value"}'

    def test_extracts_nested_object(self) -> None:
        text = 'prefix {"outer": {"inner": 1}} suffix'
        result = _extract_json_object(text)
        assert result == '{"outer": {"inner": 1}}'

    def test_handles_escaped_braces_in_string(self) -> None:
        text = '{"msg": "use \\\\{\\\\} in templates"}'
        result = _extract_json_object(text)
        assert result == text

    def test_no_brace_returns_none(self) -> None:
        assert _extract_json_object("no braces here") is None

    def test_unclosed_brace_returns_none(self) -> None:
        assert _extract_json_object('{"unclosed"') is None

    def test_empty_object(self) -> None:
        assert _extract_json_object("{}") == "{}"

    def test_first_of_two_objects(self) -> None:
        text = '{"first": 1} {"second": 2}'
        result = _extract_json_object(text)
        assert result == '{"first": 1}'

    def test_braces_inside_strings_ignored(self) -> None:
        text = '{"template": "use {placeholder} here"}'
        result = _extract_json_object(text)
        assert result == text


# ── _repair_partial_json ──────────────────────────────────────────────────────


class TestRepairPartialJson:
    def test_repairs_missing_close_brace(self) -> None:
        fragment = '{"explanation": "risk here", "fix": "do this"'
        result = _repair_partial_json(fragment)
        assert result is not None
        parsed = json.loads(result)
        assert parsed["explanation"] == "risk here"
        assert parsed["fix"] == "do this"

    def test_repairs_unclosed_string_value(self) -> None:
        fragment = '{"explanation": "risk here'
        result = _repair_partial_json(fragment)
        assert result is not None
        parsed = json.loads(result)
        assert "risk here" in parsed["explanation"]

    def test_repairs_nested_unclosed(self) -> None:
        fragment = '{"outer": {"inner": "value"'
        result = _repair_partial_json(fragment)
        assert result is not None
        parsed = json.loads(result)
        assert parsed["outer"]["inner"] == "value"

    def test_already_balanced_returns_none(self) -> None:
        complete = '{"key": "value"}'
        assert _repair_partial_json(complete) is None

    def test_no_brace_returns_none(self) -> None:
        assert _repair_partial_json("no braces") is None

    def test_garbage_returns_none(self) -> None:
        # "{{{" cannot be repaired into valid JSON
        assert _repair_partial_json("{{{") is None

    def test_result_is_dict(self) -> None:
        fragment = '{"a": 1'
        result = _repair_partial_json(fragment)
        assert result is not None
        assert isinstance(json.loads(result), dict)

    def test_prose_prefix_handled(self) -> None:
        fragment = 'Here is JSON: {"explanation": "hello"'
        result = _repair_partial_json(fragment)
        assert result is not None
        parsed = json.loads(result)
        assert parsed["explanation"] == "hello"


# ── parse_llm_response — main pipeline ───────────────────────────────────────


class TestParseLLMResponse:
    # ── returns None ──────────────────────────────────────────────────

    def test_empty_string_returns_none(self) -> None:
        assert parse_llm_response("") is None

    def test_whitespace_only_returns_none(self) -> None:
        assert parse_llm_response("   \n\t  ") is None

    def test_only_think_tags_returns_none(self) -> None:
        assert parse_llm_response("<think>all reasoning, nothing else</think>") is None

    # ── Strategy 2: direct JSON ───────────────────────────────────────

    def test_clean_json(self) -> None:
        payload = '{"explanation": "risk", "fix": "acl = private", "confidence": 0.9}'
        result = parse_llm_response(payload)
        assert result is not None
        assert result["explanation"] == "risk"
        assert result["fix"] == "acl = private"
        assert result["confidence"] == pytest.approx(0.9)

    def test_preserves_all_keys(self) -> None:
        payload = '{"explanation": "e", "fix": "f", "confidence": 0.8, "extra": "x"}'
        result = parse_llm_response(payload)
        assert result is not None
        assert result["extra"] == "x"

    def test_think_tags_before_json(self) -> None:
        payload = (
            "<think>Let me reason through this step by step.</think>"
            '{"explanation": "public bucket", "fix": "private", "confidence": 0.95}'
        )
        result = parse_llm_response(payload)
        assert result is not None
        assert result["explanation"] == "public bucket"
        assert "think" not in result["explanation"]

    def test_think_tags_between_json_fields(self) -> None:
        # After stripping think tags the remaining text is valid JSON
        payload = (
            '{"explanation": "risk"'
            "<think>should I add fix?</think>"
            ', "fix": "remediate", "confidence": 0.7}'
        )
        result = parse_llm_response(payload)
        assert result is not None
        assert result["explanation"] == "risk"

    # ── Strategy 3: markdown code fences ─────────────────────────────

    def test_json_in_json_fence(self) -> None:
        payload = '```json\n{"explanation": "e", "fix": "f", "confidence": 0.5}\n```'
        result = parse_llm_response(payload)
        assert result is not None
        assert result["explanation"] == "e"

    def test_json_in_plain_fence(self) -> None:
        payload = '```\n{"explanation": "e", "fix": "f", "confidence": 0.5}\n```'
        result = parse_llm_response(payload)
        assert result is not None
        assert result["explanation"] == "e"

    def test_fenced_json_with_prose_around(self) -> None:
        payload = (
            "Here is my analysis:\n"
            '```json\n{"explanation": "public", "fix": "private", "confidence": 0.9}\n```\n'
            "I hope that helps."
        )
        result = parse_llm_response(payload)
        assert result is not None
        assert result["explanation"] == "public"

    def test_think_plus_fence(self) -> None:
        payload = (
            "<think>thinking…</think>"
            '```json\n{"explanation": "e", "fix": "f", "confidence": 0.8}\n```'
        )
        result = parse_llm_response(payload)
        assert result is not None
        assert result["explanation"] == "e"

    # ── Strategy 4: JSON embedded in prose ───────────────────────────

    def test_json_after_prose_prefix(self) -> None:
        payload = (
            "The bucket is publicly accessible. Here is the structured response: "
            '{"explanation": "public read", "fix": "acl = private", "confidence": 0.9}'
        )
        result = parse_llm_response(payload)
        assert result is not None
        assert result["explanation"] == "public read"

    def test_json_before_prose_suffix(self) -> None:
        payload = (
            '{"explanation": "risk", "fix": "fix it", "confidence": 0.85}'
            " Let me know if you need more detail."
        )
        result = parse_llm_response(payload)
        assert result is not None
        assert result["explanation"] == "risk"

    def test_nested_json_in_prose(self) -> None:
        payload = (
            "Analysis complete. "
            '{"explanation": "nested", "details": {"severity": "high"}, "fix": "", "confidence": 0.7}'
        )
        result = parse_llm_response(payload)
        assert result is not None
        assert result["explanation"] == "nested"
        assert result["details"]["severity"] == "high"

    # ── Strategy 5: partial / truncated JSON ─────────────────────────

    def test_missing_close_brace(self) -> None:
        payload = '{"explanation": "public bucket", "fix": "acl = private", "confidence": 0.9'
        result = parse_llm_response(payload)
        assert result is not None
        assert result["explanation"] == "public bucket"

    def test_string_cut_mid_value(self) -> None:
        payload = '{"explanation": "The bucket is publicly accessible'
        result = parse_llm_response(payload)
        assert result is not None
        assert "The bucket is publicly accessible" in result["explanation"]

    def test_partial_preserves_complete_fields(self) -> None:
        payload = '{"explanation": "full explanation here", "fix": "acl = pri'
        result = parse_llm_response(payload)
        assert result is not None
        assert result["explanation"] == "full explanation here"

    # ── Strategy 6: prose fallback ────────────────────────────────────

    def test_pure_prose_returns_fallback(self) -> None:
        payload = (
            "The S3 bucket is publicly accessible which means anyone on the "
            "internet can read its contents."
        )
        result = parse_llm_response(payload)
        assert result is not None
        assert "S3 bucket" in result["explanation"]
        assert result["fix"] == ""
        assert result["confidence"] == pytest.approx(0.3)

    def test_prose_fallback_confidence_is_low(self) -> None:
        result = parse_llm_response("This is not JSON at all.")
        assert result is not None
        assert result["confidence"] < 0.5

    def test_single_word_returns_fallback(self) -> None:
        result = parse_llm_response("yes")
        assert result is not None
        assert isinstance(result, dict)

    # ── Return type guarantees ────────────────────────────────────────

    def test_always_returns_dict_for_nonempty_input(self) -> None:
        inputs = [
            '{"a": 1}',
            "```json\n{}\n```",
            "plain text",
            "<think>x</think>{}",
            '{"truncated"',
        ]
        for text in inputs:
            result = parse_llm_response(text)
            assert isinstance(result, dict), f"Expected dict for input: {text!r}"

    def test_result_is_never_list(self) -> None:
        result = parse_llm_response("[1, 2, 3]")
        assert result is not None
        assert isinstance(result, dict)

    def test_result_is_never_string(self) -> None:
        result = parse_llm_response('"just a json string"')
        assert result is not None
        assert isinstance(result, dict)
