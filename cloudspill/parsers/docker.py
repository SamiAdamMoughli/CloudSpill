"""Dockerfile parser — Dockerfile → IaCNode tree.

Parses Dockerfile instructions into IaCNode objects. Each instruction
(FROM, RUN, ENV, COPY, ADD, etc.) becomes a node. The overall image
becomes a parent node with instructions as children.

No external dependencies — pure line-by-line parsing.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from cloudspill.models.nodes import IaCNode

# Matches a Dockerfile instruction: INSTRUCTION arguments
# Handles multi-line continuations (trailing backslash) by design —
# we join continued lines before matching.
_INSTRUCTION_RE = re.compile(r"^(?P<instruction>[A-Z]+)\s+(?P<arguments>.+)$")

# Known Dockerfile instructions we care about for security analysis.
_KNOWN_INSTRUCTIONS = frozenset(
    {
        "FROM",
        "RUN",
        "CMD",
        "ENTRYPOINT",
        "ENV",
        "ADD",
        "COPY",
        "EXPOSE",
        "USER",
        "WORKDIR",
        "ARG",
        "LABEL",
        "VOLUME",
        "HEALTHCHECK",
        "SHELL",
        "STOPSIGNAL",
        "ONBUILD",
    }
)


def _join_continuations(lines: list[str]) -> list[tuple[int, str]]:
    """Join backslash-continued lines, preserving the starting line number.

    Returns a list of (line_number, joined_line) tuples.
    """
    result: list[tuple[int, str]] = []
    current: list[str] = []
    start_line = 1

    for i, raw in enumerate(lines, start=1):
        stripped = raw.rstrip()

        if not current:
            start_line = i

        if stripped.endswith("\\"):
            current.append(stripped[:-1].strip())
        else:
            current.append(stripped.strip())
            joined = " ".join(part for part in current if part)
            if joined:
                result.append((start_line, joined))
            current = []

    # Handle trailing continuation without final line
    if current:
        joined = " ".join(part for part in current if part)
        if joined:
            result.append((start_line, joined))

    return result


def _parse_env(arguments: str) -> dict[str, str]:
    """Parse ENV instruction arguments into key-value pairs.

    Handles both forms:
        ENV KEY=VALUE KEY2=VALUE2
        ENV KEY VALUE
    """
    pairs: dict[str, str] = {}

    if "=" in arguments:
        # KEY=VALUE form — may have multiple pairs
        for match in re.finditer(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)', arguments):
            key = match.group(1)
            value = match.group(2).strip('"')
            pairs[key] = value
    else:
        # Legacy single KEY VALUE form
        parts = arguments.split(None, 1)
        if len(parts) == 2:
            pairs[parts[0]] = parts[1]
        elif len(parts) == 1:
            pairs[parts[0]] = ""

    return pairs


def _parse_from(arguments: str) -> dict[str, Any]:
    """Parse FROM instruction into image, tag, and optional alias.

    Handles: image, image:tag, image:tag AS alias, image@digest
    """
    attrs: dict[str, Any] = {}

    # Handle AS alias
    as_match = re.match(r"(.+?)\s+[Aa][Ss]\s+(\S+)", arguments)
    if as_match:
        image_part = as_match.group(1).strip()
        attrs["alias"] = as_match.group(2)
    else:
        image_part = arguments.strip()

    # Handle digest
    if "@" in image_part:
        image, digest = image_part.rsplit("@", 1)
        attrs["image"] = image
        attrs["digest"] = digest
        attrs["tag"] = ""
    elif ":" in image_part:
        image, tag = image_part.rsplit(":", 1)
        attrs["image"] = image
        attrs["tag"] = tag
    else:
        attrs["image"] = image_part
        attrs["tag"] = "latest"

    return attrs


class DockerfileParser:
    """Parses Dockerfiles into typed IaCNode trees."""

    def can_parse(self, path: Path) -> bool:
        """Return True for Dockerfile variants."""
        return path.name.lower().startswith("dockerfile")

    def parse(self, path: Path) -> list[IaCNode]:
        """Parse a Dockerfile into a list of IaCNodes.

        Returns one node per instruction. The node_id format is
        'dockerfile.<filename>.<INSTRUCTION>.<index>' to ensure uniqueness.
        """
        source = path.read_text(encoding="utf-8")
        raw_lines = source.splitlines()
        logical_lines = _join_continuations(raw_lines)

        nodes: list[IaCNode] = []
        source_file = str(path)
        filename = path.stem.lower()
        instruction_counts: dict[str, int] = {}

        for line_no, line_text in logical_lines:
            # Skip comments and blank lines
            if not line_text or line_text.startswith("#"):
                continue

            match = _INSTRUCTION_RE.match(line_text)
            if not match:
                continue

            instruction = match.group("instruction").upper()
            arguments = match.group("arguments").strip()

            if instruction not in _KNOWN_INSTRUCTIONS:
                continue

            # Track instruction index for unique node_ids
            count = instruction_counts.get(instruction, 0)
            instruction_counts[instruction] = count + 1

            node_id = f"dockerfile.{filename}.{instruction}.{count}"
            attributes = self._build_attributes(instruction, arguments)

            nodes.append(
                IaCNode(
                    node_id=node_id,
                    node_type="instruction",
                    resource_type=instruction,
                    name=f"{instruction} {arguments}",
                    attributes=attributes,
                    children=(),
                    source_file=source_file,
                    line=line_no,
                )
            )

        return nodes

    def _build_attributes(self, instruction: str, arguments: str) -> dict[str, Any]:
        """Build typed attribute dicts based on instruction type."""
        match instruction:
            case "FROM":
                return _parse_from(arguments)
            case "ENV":
                return _parse_env(arguments)
            case "RUN":
                return {"command": arguments}
            case "CMD" | "ENTRYPOINT":
                return {"command": arguments}
            case "COPY":
                parts = arguments.split()
                return {
                    "src": parts[0] if parts else "",
                    "dst": parts[-1] if len(parts) > 1 else "",
                }
            case "ADD":
                parts = arguments.split()
                return {
                    "src": parts[0] if parts else "",
                    "dst": parts[-1] if len(parts) > 1 else "",
                }
            case "EXPOSE":
                return {"port": arguments}
            case "USER":
                return {"user": arguments}
            case "WORKDIR":
                return {"path": arguments}
            case "ARG":
                if "=" in arguments:
                    key, _, value = arguments.partition("=")
                    return {"name": key, "default": value}
                return {"name": arguments}
            case _:
                return {"raw": arguments}
