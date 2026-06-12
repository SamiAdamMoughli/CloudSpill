"""Finding and Severity — pure rule-engine output."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Finding severity levels, ordered from most to least severe."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class Finding:
    """A single rule violation detected during static analysis."""

    rule_id: str
    severity: Severity
    title: str
    description: str
    resource: str
    file: str
    line: int
    # Optional metadata — rules should populate these when known.
    # tags: compliance frameworks and categories (e.g. "cis-1.3.2", "public-access")
    # remediation: a short, actionable fix description for this specific finding
    # references: URLs to relevant documentation or CVEs
    tags: frozenset[str] = field(default_factory=frozenset)
    remediation: str | None = None
    references: tuple[str, ...] = field(default_factory=tuple)
