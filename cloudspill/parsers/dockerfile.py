"""Dockerfile parser — Dockerfile → IaCNode tree."""

from __future__ import annotations

from pathlib import Path

from cloudspill.models.nodes import IaCNode


class DockerfileParser:
def can_parse(self, path: Path) -> bool:
return path.name.lower().startswith("dockerfile")

def parse(self, path: Path) -> list[IaCNode]:
raise NotImplementedError
