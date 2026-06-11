"""Finding and Severity — pure rule-engine output."""

from __future__ import annotations

from dataclasses import dataclass
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
