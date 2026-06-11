"""ParserRegistry — maps file types to parsers, runs parse_all."""

from __future__ import annotations

from pathlib import Path

from cloudspill.models.nodes import IaCNode
from cloudspill.parsers.base import Parser
from cloudspill.parsers.dockerfile import DockerfileParser
from cloudspill.parsers.terraform import TerraformParser


class ParserRegistry:
    """Holds all available parsers and dispatches files to the right one."""

    def __init__(self) -> None:
        self._parsers: list[Parser] = [
            TerraformParser(),
            DockerfileParser(),
        ]

    def parse_all(self, paths: list[Path]) -> list[IaCNode]:
        """Parse every file that has a matching parser. Skip the rest."""
        raise NotImplementedError
