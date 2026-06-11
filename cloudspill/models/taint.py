"""TaintResult and TaintPath — taint-engine output, separate from findings."""

from __future__ import annotations

from dataclasses import dataclass

from cloudspill.models.findings import Finding
from cloudspill.models.graph import EdgeKind


@dataclass(frozen=True)
class TaintPath:
    """A single propagation chain through the resource graph."""

    nodes: tuple[str, ...]
    edges: tuple[EdgeKind, ...]
    risk: str


@dataclass(frozen=True)
class TaintResult:
    """All propagation paths originating from a single finding."""

    finding: Finding
    paths: tuple[TaintPath, ...]
