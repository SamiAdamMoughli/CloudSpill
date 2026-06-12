"""ParserRegistry — maps file types to parsers, runs parse_all."""

from __future__ import annotations

import logging
from pathlib import Path

from cloudspill.models.errors import ParseError
from cloudspill.models.nodes import IaCNode
from cloudspill.parsers.base import Parser
from cloudspill.parsers.docker import DockerfileParser
from cloudspill.parsers.terraform import TerraformParser

logger = logging.getLogger(__name__)


class ParserRegistry:  # pylint: disable=too-few-public-methods
    """Holds all available parsers and dispatches files to the right one.

    After calling parse_all(), any files that failed to parse are
    available in self.errors for inclusion in ScanMetadata.
    """

    def __init__(self) -> None:
        self._parsers: list[Parser] = [
            TerraformParser(),
            DockerfileParser(),
        ]
        self.errors: list[ParseError] = []

    def parse_all(self, paths: list[Path]) -> list[IaCNode]:
        """Parse every file that has a matching parser. Skip the rest.

        Parse failures are recorded in self.errors rather than raised,
        so one bad file does not abort the entire scan.
        """
        self.errors.clear()
        nodes: list[IaCNode] = []
        for path in paths:
            for parser in self._parsers:
                if parser.can_parse(path):
                    try:
                        nodes.extend(parser.parse(path))
                    except (OSError, ValueError, SyntaxError) as exc:
                        logger.warning("Failed to parse %s: %s", path, exc)
                        self.errors.append(ParseError(file=str(path), message=str(exc)))
                    except Exception as exc:  # pylint: disable=broad-except
                        # HCL grammar errors surface as library-specific types;
                        # keep the scan alive but record and log them.
                        logger.warning("Unexpected error parsing %s: %s", path, exc)
                        logger.debug("Parse traceback for %s", path, exc_info=True)
                        self.errors.append(ParseError(file=str(path), message=str(exc)))
                    break
        return nodes
