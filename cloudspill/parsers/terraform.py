"""Terraform HCL parser — HCL → JSON → IaCNode tree.

Uses a two-pass strategy:
  1. hcl2.load() for clean attribute dictionaries.
  2. Regex scan on raw source for block start-line numbers.

hcl2 v8+ wraps string keys and values in extra quotes — this parser
strips them transparently so downstream consumers see clean data.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import hcl2

from cloudspill.models.nodes import IaCNode

# Matches: resource "aws_s3_bucket" "name" {
# Also:    data "aws_iam_policy_document" "name" {
#          variable "name" {
#          output "name" {
#          locals {
#          module "name" {
_BLOCK_RE = re.compile(
    r'^(?P<type>resource|data|variable|output|locals|module)'
    r'\s+"?(?P<label1>[^"\s]+)"?'
    r'(?:\s+"?(?P<label2>[^"\s{]+)"?)?'
    r'\s*\{',
)

# HCL top-level block types that produce IaCNodes.
_TOP_LEVEL_TYPES = frozenset({"resource", "data", "variable", "output", "locals", "module"})


def _strip_hcl2_quotes(value: str) -> str:
    """Remove the extra surrounding quotes that hcl2 v8+ adds to strings."""
    if isinstance(value, str) and len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _clean_attributes(raw: dict[str, Any]) -> dict[str, Any]:
    """Recursively strip hcl2 quote artifacts from keys and string values."""
    cleaned: dict[str, Any] = {}
    for key, value in raw.items():
        if key.startswith("__"):
            continue
        clean_key = _strip_hcl2_quotes(key)
        cleaned[clean_key] = _clean_value(value)
    return cleaned


def _clean_value(value: Any) -> Any:
    """Strip quotes from a single value, recursing into dicts and lists."""
    if isinstance(value, str):
        return _strip_hcl2_quotes(value)
    if isinstance(value, dict):
        return _clean_attributes(value)
    if isinstance(value, list):
        return [_clean_value(item) for item in value]
    return value


def _extract_children(attributes: dict[str, Any], source_file: str, parent_id: str, line: int) -> tuple[dict[str, Any], tuple[IaCNode, ...]]:
    """Separate nested block dicts from scalar attributes.

    Returns (flat_attributes, children_tuple).
    Nested dicts that look like sub-blocks (tags, provisioner, etc.)
    become child IaCNodes.
    """
    flat: dict[str, Any] = {}
    children: list[IaCNode] = []

    for key, value in attributes.items():
        if isinstance(value, dict) and not _looks_like_reference(value):
            child_node = IaCNode(
                node_id=f"{parent_id}.{key}",
                node_type="block",
                resource_type=key,
                name=key,
                attributes=value,
                children=(),
                source_file=source_file,
                line=line,
            )
            children.append(child_node)
        else:
            flat[key] = value

    return flat, tuple(children)


def _looks_like_reference(value: dict[str, Any]) -> bool:
    """Heuristic: dicts with only string-valued keys are tag maps, not blocks."""
    return all(isinstance(v, (str, int, float, bool)) for v in value.values())


def _scan_line_numbers(source: str) -> dict[str, int]:
    """Regex pass over raw HCL to map 'type.label1.label2' → line number."""
    line_map: dict[str, int] = {}
    for line_no, line_text in enumerate(source.splitlines(), start=1):
        match = _BLOCK_RE.match(line_text.strip())
        if match:
            block_type = match.group("type")
            label1 = match.group("label1")
            label2 = match.group("label2")
            if label2:
                key = f"{label1}.{label2}"
            elif label1:
                key = f"{block_type}.{label1}"
            else:
                key = block_type
            line_map[key] = line_no
    return line_map


class TerraformParser:
    """Parses .tf files into typed IaCNode trees."""

    def can_parse(self, path: Path) -> bool:
        """Return True for Terraform files."""
        return path.suffix == ".tf"

    def parse(self, path: Path) -> list[IaCNode]:
        """Parse a single .tf file into a list of IaCNodes.

        Each top-level resource/data/variable/output/module block becomes
        one IaCNode. Nested blocks (tags, provisioner, etc.) become children.
        """
        source = path.read_text(encoding="utf-8")
        line_map = _scan_line_numbers(source)

        with open(path, encoding="utf-8") as f:
            raw = hcl2.load(f)

        nodes: list[IaCNode] = []

        for block_type in _TOP_LEVEL_TYPES:
            for block in raw.get(block_type, []):
                if not isinstance(block, dict):
                    continue
                nodes.extend(
                    self._parse_block(block_type, block, str(path), line_map)
                )

        return nodes

    def _parse_block(
        self,
        block_type: str,
        block: dict[str, Any],
        source_file: str,
        line_map: dict[str, int],
    ) -> list[IaCNode]:
        """Convert a single hcl2 block dict into one or more IaCNodes."""
        nodes: list[IaCNode] = []

        for raw_resource_type, resources in block.items():
            resource_type = _strip_hcl2_quotes(raw_resource_type)

            if not isinstance(resources, dict):
                continue

            for raw_name, raw_attrs in resources.items():
                name = _strip_hcl2_quotes(raw_name)

                if block_type == "resource":
                    node_id = f"{resource_type}.{name}"
                elif block_type == "data":
                    node_id = f"data.{resource_type}.{name}"
                else:
                    node_id = f"{block_type}.{name}"

                line = line_map.get(f"{resource_type}.{name}", 0) or line_map.get(f"{block_type}.{name}", 0)

                attributes = _clean_attributes(raw_attrs) if isinstance(raw_attrs, dict) else {}
                flat_attrs, children = _extract_children(attributes, source_file, node_id, line)

                nodes.append(IaCNode(
                    node_id=node_id,
                    node_type=block_type,
                    resource_type=resource_type,
                    name=name,
                    attributes=flat_attrs,
                    children=children,
                    source_file=source_file,
                    line=line,
                ))

        return nodes
