"""AIEnricher — LLM-based enrichment using a local inference server.

Calls a local model (Qwen3.6-35B-A3B, Gemma 4 31B QAT, etc.) via an
OpenAI-compatible /v1/chat/completions endpoint. Falls back gracefully
if the server is unreachable, returning a degraded EnrichedFinding with
an explanation noting the model was unavailable rather than failing the scan.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx

from cloudspill.enrichers.types import EnrichedFinding
from cloudspill.models.findings import Finding
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.taint import TaintResult

_SYSTEM_PROMPT = (
    "You are a cloud security expert. You will be given a security finding "
    "from a static analysis tool. Respond with a JSON object containing:\n"
    '  "explanation": a 2-3 sentence plain-English explanation of the risk\n'
    '  "fix": a short Terraform or Dockerfile snippet that fixes it\n'
    '  "confidence": a float 0.0–1.0 representing your certainty\n'
    "Return only the JSON object, no prose, no markdown code fences."
)

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)

_UNAVAILABLE = "[AI unavailable]"


def _read_source_context(file: str, line: int, window: int = 5) -> str:
    """Return a windowed excerpt of `file` centred on `line`, with numbers."""
    try:
        lines = Path(file).read_text(encoding="utf-8").splitlines()
    except OSError:
        return f"Could not read {file}"

    start = max(0, line - 1 - window)
    end = min(len(lines), line + window)
    return "\n".join(
        f"{i + 1} | {lines[i]}" for i in range(start, end)
    )


def _build_prompt(
    finding: Finding,
    taint: TaintResult | None,
    source_context: str,
) -> str:
    """Build the user message sent to the model."""
    lines = [
        f"Rule: {finding.rule_id}",
        f"Severity: {finding.severity.value}",
        f"Title: {finding.title}",
        f"Description: {finding.description}",
        f"Resource: {finding.resource}",
        f"File: {finding.file}:{finding.line}",
        "",
        "Source context:",
        source_context,
        "",
    ]

    if taint and taint.paths:
        lines.append("Taint propagation:")
        for path in taint.paths[:3]:
            chain = " → ".join(path.nodes)
            kinds = ", ".join(e.value for e in path.edges)
            lines.append(f"  {chain} [{kinds}]")
    else:
        lines.append("No downstream propagation detected.")

    return "\n".join(lines)


class AIEnricher:
    """Enriches findings with LLM-generated explanations and fix patches."""

    def __init__(
        self,
        model: str = "qwen3.6-35b-a3b",
        base_url: str = "http://localhost:11434/v1",
        timeout: int = 30,
        temperature: float = 0.1,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/") + "/chat/completions"
        self.temperature = temperature
        self._timeout = timeout

    def enrich(
        self,
        findings: list[Finding],
        taint_results: list[TaintResult],
        _graph: ResourceGraph,
    ) -> list[EnrichedFinding]:
        """Call the local model for each finding. One result per finding."""
        taint_index: dict[str, TaintResult] = {
            tr.finding.rule_id: tr for tr in taint_results
        }
        return [
            self._enrich_one(f, taint_index.get(f.rule_id))
            for f in findings
        ]

    def _enrich_one(
        self,
        finding: Finding,
        taint: TaintResult | None,
    ) -> EnrichedFinding:
        source = _read_source_context(finding.file, finding.line)
        prompt = _build_prompt(finding, taint, source)
        parsed = self._call_model(prompt)

        if parsed is None:
            return EnrichedFinding(
                finding=finding,
                explanation=f"{_UNAVAILABLE} model server unreachable.",
                remediation_patch="",
                confidence=0.0,
                model=self.model,
            )

        return EnrichedFinding(
            finding=finding,
            explanation=parsed.get("explanation", ""),
            remediation_patch=parsed.get("fix", ""),
            confidence=float(parsed.get("confidence", 1.0)),
            model=self.model,
        )

    def _call_model(self, prompt: str) -> dict[str, Any] | None:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": self.temperature,
        }

        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(self.base_url, json=payload)
                response.raise_for_status()
                body: dict[str, Any] = response.json()

            content = body["choices"][0]["message"]["content"].strip()
            content = self._strip_thinking(content)
            return json.loads(content)
        except Exception:  # pylint: disable=broad-except
            return None

    @staticmethod
    def _strip_thinking(content: str) -> str:
        """Remove <think>...</think> blocks before JSON parsing."""
        return _THINK_RE.sub("", content).strip()
