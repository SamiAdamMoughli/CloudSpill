"""AI enricher — LLM-powered narrative generation via Qwen3.6-35B-A3B.

Transforms raw findings and taint paths into human-readable threat
narratives and direct infrastructure patches using a local reasoning
model served via Ollama or vLLM (OpenAI-compatible API).

Usage:
    cloudspill ./infra --ai
    cloudspill ./infra --ai --model qwen3.6-35b-a3b
    cloudspill ./infra --ai --ai-url http://localhost:8000/v1
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from cloudspill.models.findings import Finding
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.taint import TaintPath, TaintResult

_SYSTEM_PROMPT = """\
You are CloudSpill-AI, an expert cloud security architect and infrastructure engineer.

You analyze Infrastructure-as-Code security findings with their taint propagation paths \
and produce actionable remediation guidance.

For each finding you receive, respond ONLY with a valid JSON object matching this schema:
{
    "explanation": "A concise markdown narrative (2-4 sentences) explaining the security risk, \
how the misconfiguration propagates through the infrastructure graph, and the real-world \
attack scenario it enables.",
    "fix": "The exact corrected HCL or Dockerfile block that resolves this finding. \
Include only the minimal change needed. Use code fences with the appropriate language."
}

Do NOT include any text outside the JSON object. Do NOT wrap in markdown code fences."""


def _build_prompt(
    finding: Finding,
    taint: TaintResult | None,
    source_context: str,
) -> str:
    """Build the user prompt for a single finding."""
    taint_section = "No downstream propagation detected."
    if taint and taint.paths:
        chains: list[str] = []
        for tp in taint.paths:
            chain = " → ".join(tp.nodes)
            edges = ", ".join(e.value for e in tp.edges)
            chains.append(f"  {chain}  (via {edges})")
        taint_section = "Taint propagation paths:\n" + "\n".join(chains)

    return f"""\
Analyze this Infrastructure-as-Code security finding:

Rule: {finding.rule_id} — {finding.title}
Severity: {finding.severity.value}
Resource: {finding.resource}
Location: {finding.file} at line {finding.line}
Description: {finding.description}

{taint_section}

Source context:
```
{source_context}
```"""


def _read_source_context(file_path: str, line: int, window: int = 5) -> str:
    """Extract lines around the finding for LLM context."""
    try:
        with open(file_path, encoding="utf-8") as f:
            lines = f.readlines()
        start = max(0, line - window - 1)
        end = min(len(lines), line + window)
        numbered = [
            f"{i + 1:4d} | {lines[i].rstrip()}"
            for i in range(start, end)
        ]
        return "\n".join(numbered)
    except (OSError, IndexError):
        return f"# Could not read source: {file_path}"


class AIEnricher:
    """Enriches findings with LLM-generated narratives and remediation patches.

    Connects to a local OpenAI-compatible API to generate context-aware
    explanations and fixes for each finding, incorporating taint propagation
    data for graph-aware reasoning.
    """

    def __init__(
        self,
        model: str = "qwen3.6-35b-a3b",
        base_url: str = "http://localhost:11434/v1",
        timeout: float = 60.0,
        temperature: float = 0.2,
    ) -> None:
        self.model = model
        self.base_url = f"{base_url.rstrip('/')}/chat/completions"
        self.timeout = timeout
        self.temperature = temperature

    def enrich(
        self,
        findings: list[Finding],
        taint_results: list[TaintResult],
        graph: ResourceGraph,
    ) -> list[dict[str, Any]]:
        """Generate AI enrichment for all findings.

        Returns one dict per finding with 'explanation' and 'fix' keys.
        Failures are handled per-finding — one timeout won't kill the batch.
        """
        taint_map: dict[str, TaintResult] = {}
        for tr in taint_results:
            taint_map.setdefault(tr.finding.resource, tr)

        results: list[dict[str, Any]] = []
        for finding in findings:
            taint = taint_map.get(finding.resource)
            result = self._enrich_single(finding, taint)
            results.append(result)

        return results

    def _enrich_single(
        self,
        finding: Finding,
        taint: TaintResult | None,
    ) -> dict[str, Any]:
        """Query the local model for a single finding."""
        source_context = _read_source_context(finding.file, finding.line)
        user_prompt = _build_prompt(finding, taint, source_context)

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.temperature,
            "max_tokens": 1024,
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    self.base_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
                response.raise_for_status()
                data = response.json()

                content = data["choices"][0]["message"]["content"]
                # Strip thinking tags if present (Qwen3.6 reasoning output)
                content = self._strip_thinking(content)
                parsed = json.loads(content)

                return {
                    "rule_id": finding.rule_id,
                    "resource": finding.resource,
                    "explanation": parsed.get("explanation", ""),
                    "fix": parsed.get("fix", ""),
                }

        except httpx.ConnectError:
            return self._fallback(finding, "No inference server running. Start Ollama or vLLM.")
        except httpx.TimeoutException:
            return self._fallback(finding, f"Model timed out after {self.timeout}s.")
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            return self._fallback(finding, f"Failed to parse model response: {e}")
        except httpx.HTTPStatusError as e:
            return self._fallback(finding, f"API error: {e.response.status_code}")

    @staticmethod
    def _strip_thinking(content: str) -> str:
        """Remove <think>...</think> blocks from Qwen3.6 reasoning output."""
        import re

        return re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

    @staticmethod
    def _fallback(finding: Finding, reason: str) -> dict[str, Any]:
        return {
            "rule_id": finding.rule_id,
            "resource": finding.resource,
            "explanation": f"[AI unavailable] {reason}",
            "fix": "# Manual remediation required.",
        }
