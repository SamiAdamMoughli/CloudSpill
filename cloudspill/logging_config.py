"""Centralised logging setup for CloudSpill.

All diagnostic output goes through the standard library ``logging`` module to
**stderr**, so it never contaminates machine-readable results (JSON, Mermaid)
written to stdout. Modules log via ``logging.getLogger(__name__)``; the CLI
calls :func:`configure_logging` once at startup to set the level and handler.

Verbosity ladder:

    (default)      WARNING   — only problems
    -v             INFO      — pipeline progress, provider activity
    -vv / --debug  DEBUG     — per-stage detail, full tracebacks on error
"""

from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler

ROOT_LOGGER_NAME = "cloudspill"


def configure_logging(verbosity: int = 0, *, debug: bool = False) -> None:
    """Configure the ``cloudspill`` logger hierarchy.

    Args:
        verbosity: number of ``-v`` flags (0 → WARNING, 1 → INFO, 2+ → DEBUG).
        debug: force DEBUG level and rich tracebacks regardless of verbosity.
    """
    if debug or verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    logger = logging.getLogger(ROOT_LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False
    logger.handlers.clear()

    handler = RichHandler(
        console=Console(stderr=True),
        show_time=False,
        show_path=debug,
        rich_tracebacks=debug,
        markup=False,
    )
    handler.setLevel(level)
    logger.addHandler(handler)
