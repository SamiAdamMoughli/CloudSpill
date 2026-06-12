"""AIEnricher — LLM-based enrichment, provider-agnostic.

Accepts any LLMProvider (local Ollama, OpenAI, Anthropic, …). Falls back
gracefully if the provider raises, returning a degraded EnrichedFinding with
an explanation noting the model was unavailable rather than failing the scan.

System prompts are loaded from enrichers/prompts/<mode>.txt at runtime.
Raw LLM output is normalised by enrichers/parser.parse_llm_response — all
format-handling logic lives there, not here.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from cloudspill.enrichers.parser import parse_llm_response
from cloudspill.enrichers.prompts import PromptLoader
from cloudspill.enrichers.types import EnrichedFinding
from cloudspill.models.findings import Finding
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.taint import TaintResult

logger = logging.getLogger(__name__)

_UNAVAILABLE = "[AI unavailable]"


class _RateLimiter:
    """Token-bucket rate limiter — thread-safe, based on wall-clock time."""

    def __init__(self, rpm: int) -> None:
        self._interval = 60.0 / rpm
        self._next_allowed = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._next_allowed - now
            if wait > 0:
                time.sleep(wait)
            self._next_allowed = time.monotonic() + self._interval


def _read_source_context(file: str, line: int, window: int = 5) -> str:
    """Return a windowed excerpt of `file` centred on `line`, with numbers."""
    try:
        lines = Path(file).read_text(encoding="utf-8").splitlines()
    except OSError:
        return f"Could not read {file}"

    start = max(0, line - 1 - window)
    end = min(len(lines), line + window)
    return "\n".join(f"{i + 1} | {lines[i]}" for i in range(start, end))


def _taint_summary(taint: TaintResult | None) -> str:
    """One-line summary of taint paths, or 'none'."""
    if not taint or not taint.paths:
        return "none"
    parts = []
    for path in taint.paths[:3]:
        chain = " → ".join(path.nodes)
        kinds = ", ".join(e.value for e in path.edges)
        parts.append(f"{chain} [{kinds}]")
    return "; ".join(parts)


def _build_prompt(
    finding: Finding,
    taint: TaintResult | None,
    source_context: str,
) -> str:
    """Build the user message sent to the model.

    Kept as a module-level function so tests can import and unit-test it
    independently of AIEnricher.
    """
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
    """Enriches findings with LLM-generated explanations and fix patches.

    Pass a `provider` to use a specific backend (OpenAI, Anthropic, …).
    Defaults to OpenAICompatProvider (local Ollama / vLLM / LM Studio).

    Pass `mode` to select which prompt template is used:
        explain  — plain-English risk explanation (default)
        fix      — minimal remediation snippet
        triage   — true-positive / false-positive assessment
    """

    def __init__(
        self,
        model: str = "qwen3.6-35b-a3b",
        base_url: str = "http://localhost:11434/v1",
        timeout: int = 120,
        temperature: float = 0.1,
        provider: Any = None,
        mode: str = "explain",
        rpm_limit: int | None = None,
        provider_name: str = "default",
    ) -> None:
        from cloudspill.enrichers.prompts import VALID_MODES
        from cloudspill.enrichers.providers.openai_compat import OpenAICompatProvider

        if mode not in VALID_MODES:
            raise ValueError(
                f"Unknown mode '{mode}'. Choose from: {', '.join(sorted(VALID_MODES))}"
            )

        self.model = model
        self.base_url = base_url.rstrip("/") + "/chat/completions"
        self.temperature = temperature
        self.mode = mode
        self._last_error: str = ""
        self._rate_limiter = _RateLimiter(rpm_limit) if rpm_limit else None
        self._provider_name = provider_name
        self._provider = provider or OpenAICompatProvider(
            base_url=base_url,
            model=model,
            temperature=temperature,
            timeout=timeout,
        )

    def enrich(
        self,
        findings: list[Finding],
        taint_results: list[TaintResult],
        graph: ResourceGraph,  # pylint: disable=unused-argument
    ) -> list[EnrichedFinding]:
        """Call the provider for each finding concurrently."""
        if not findings:
            return []

        from rich.progress import (  # noqa: PLC0415
            BarColumn,
            Progress,
            SpinnerColumn,
            TaskProgressColumn,
            TextColumn,
            TimeElapsedColumn,
        )

        taint_index: dict[str, TaintResult] = {
            tr.finding.rule_id: tr for tr in taint_results
        }
        # Preserve original order in the output.
        ordered: list[EnrichedFinding | None] = [None] * len(findings)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[dim]{task.fields[current]}"),
            TimeElapsedColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task(
                f"AI [{self.mode}]  {self.model}",
                total=len(findings),
                current="",
            )

            def _run(idx: int, f: Finding) -> tuple[int, EnrichedFinding]:
                if self._rate_limiter:
                    self._rate_limiter.acquire()
                result = self._enrich_one(f, taint_index.get(f.rule_id))
                return idx, result

            workers = min(len(findings), 5)
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {pool.submit(_run, i, f): f for i, f in enumerate(findings)}
                for future in as_completed(futures):
                    idx, enriched = future.result()
                    ordered[idx] = enriched
                    progress.update(task, current=futures[future].rule_id)
                    progress.advance(task)

        return [r for r in ordered if r is not None]

    def _enrich_one(
        self,
        finding: Finding,
        taint: TaintResult | None,
    ) -> EnrichedFinding:
        source = _read_source_context(finding.file, finding.line)
        user_prompt = _build_prompt(finding, taint, source)
        system_prompt = PromptLoader.render(
            self.mode,
            provider=self._provider_name,
            rule_id=finding.rule_id,
            severity=finding.severity.value,
            title=finding.title,
            description=finding.description,
            resource=finding.resource,
            file=finding.file,
            line=str(finding.line),
            tags=", ".join(sorted(finding.tags)) if finding.tags else "none",
            remediation=finding.remediation or "not specified",
            taint_summary=_taint_summary(taint),
            source_context=source,
        )
        parsed = self._call_model(system_prompt, user_prompt)

        if parsed is None:
            detail = f": {self._last_error}" if self._last_error else ""
            return EnrichedFinding(
                finding=finding,
                explanation=f"{_UNAVAILABLE}{detail}",
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

    def _call_model(self, system: str, user: str) -> dict[str, Any] | None:
        # Providers raise on any failure; we degrade gracefully rather than
        # aborting the whole scan, but record and log the reason so it is
        # visible under -v / --debug instead of silently swallowed.
        try:
            content = self._provider.complete(system, user)
            return parse_llm_response(content)
        except Exception as exc:  # pylint: disable=broad-except
            self._last_error = str(exc)
            logger.warning("Enrichment call failed: %s", exc)
            logger.debug("Provider error detail", exc_info=True)
            return None
