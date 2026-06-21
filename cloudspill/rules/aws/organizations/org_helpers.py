"""Shared helpers for the AWS Organizations rule set.

The policy-type rules (ORG-001, ORG-004..ORG-006) all read the same two fields
off ``aws_organizations_organization``: ``feature_set`` and the
``enabled_policy_types`` list. These helpers normalize those and answer the
"does this org actually govern?" question, so the rules can skip an org that is
consolidated-billing only (where no policy type can be enabled — ORG-003 is the
single, accurate finding for that case).

This module registers no rules; it is imported by the ``org_*`` rule modules.
"""

from __future__ import annotations

from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_str_list


def feature_set(node: IaCNode) -> str:
    """The org's feature_set, upper-cased; defaults to ALL when unset."""
    value = node.attributes.get("feature_set")
    return str(value).strip().upper() if value else "ALL"


def enabled_policy_types(node: IaCNode) -> set[str]:
    """The set of enabled_policy_types, upper-cased."""
    return {
        t.strip().upper()
        for t in as_str_list(node.attributes.get("enabled_policy_types"))
    }


def governs(node: IaCNode) -> bool:
    """True if the org has ALL features (so policy types can be enabled)."""
    return feature_set(node) == "ALL"
