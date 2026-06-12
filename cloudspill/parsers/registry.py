"""ParserRegistry — maps file types to parsers, runs parse_all."""

from __future__ import annotations

from pathlib import Path

from cloudspill.models.nodes import IaCNode
from cloudspill.parsers.base import Parser
from cloudspill.parsers.docker import DockerfileParser
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
        nodes: list[IaCNode] = []
        for path in paths:
            for parser in self._parsers:
                if parser.can_parse(path):
                    nodes.extend(parser.parse(path))
                    break
        return nodes
