"""Shared helpers for GuardDuty protection-feature rules.

GuardDuty's optional protections can be configured two ways depending on
provider version:

* the modern per-feature resource ``aws_guardduty_detector_feature``
  (``name = "S3_DATA_EVENTS"``, ``status = "ENABLED" | "DISABLED"``), and
* the legacy ``datasources { ... }`` block on ``aws_guardduty_detector``
  (e.g. ``datasources { s3_logs { enable = false } }``).

Each GD-002..GD-005 rule checks both shapes through these helpers. This module
registers no rules; it is imported by the ``gd_*`` rule modules.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks


def _explicitly_false(value: Any) -> bool:
    """True only when an enable flag is present and a false-y value."""
    if value is None:
        return False
    if isinstance(value, bool):
        return value is False
    return str(value).strip().lower() == "false"


def detector_feature_disabled(node: IaCNode, *names: str) -> bool:
    """True if an aws_guardduty_detector_feature for `names` is not ENABLED."""
    if node.resource_type != "aws_guardduty_detector_feature":
        return False
    name = str(node.attributes.get("name", "")).strip().upper()
    if name not in {n.upper() for n in names}:
        return False
    status = str(node.attributes.get("status", "")).strip().upper()
    return status != "ENABLED"


def legacy_datasource_disabled(node: IaCNode, *path: str) -> bool:
    """True if a legacy datasources block at `path` has enable explicitly false.

    `path` walks nested blocks, e.g. ``("s3_logs",)`` or
    ``("kubernetes", "audit_logs")``.
    """
    if node.resource_type != "aws_guardduty_detector":
        return False
    current = as_blocks(node.attributes.get("datasources"))
    for key in path:
        current = [child for blk in current for child in as_blocks(blk.get(key))]
    return any(_explicitly_false(blk.get("enable")) for blk in current)
