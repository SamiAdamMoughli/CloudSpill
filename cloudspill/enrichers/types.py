"""EnrichedFinding — typed output of the enricher pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field

from cloudspill.models.findings import Finding


@dataclass(frozen=True)
class EnrichedFinding:
    """A finding augmented by an enricher (e.g. an LLM explanation + patch)."""

    finding: Finding
    explanation: str
    remediation_patch: str
    confidence: float = 1.0
    model: str = ""
    extra: tuple[tuple[str, str], ...] = field(default_factory=tuple)
