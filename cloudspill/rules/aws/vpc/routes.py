"""Shared route extraction for the VPC routing rules.

A route can be a standalone ``aws_route`` resource or an inline ``route`` block on
``aws_route_table``. VPC-004 and VPC-006 both need to iterate routes uniformly,
so this helper normalizes both shapes into a list of route dicts. It registers no
rules; it is imported by the ``vpc_*`` rule modules.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks

_INTERNET_GATEWAY_HINTS = ("aws_internet_gateway", "igw-")
_OPEN_CIDRS = frozenset({"0.0.0.0/0", "::/0"})


def routes(node: IaCNode) -> list[dict[str, Any]]:
    """Route dicts from an aws_route resource or aws_route_table inline blocks."""
    if node.resource_type == "aws_route":
        return [node.attributes]
    if node.resource_type in ("aws_route_table", "aws_default_route_table"):
        blocks = as_blocks(node.attributes.get("route"))
        blocks += [c.attributes for c in node.children if c.resource_type == "route"]
        return blocks
    return []


def destination(route: dict[str, Any]) -> str:
    return str(route.get("destination_cidr_block", "")).strip()


def is_default_route(route: dict[str, Any]) -> bool:
    return destination(route) in _OPEN_CIDRS


def targets_internet_gateway(route: dict[str, Any]) -> bool:
    gateway = str(route.get("gateway_id", "")).strip().lower()
    return bool(gateway) and any(h in gateway for h in _INTERNET_GATEWAY_HINTS)
