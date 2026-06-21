"""Shared parsing helpers for the IAM rule set.

The IAM rules inspect two kinds of policy document on IAM resources:

* *identity policies* — the ``policy`` attribute on ``aws_iam_policy`` and the
  inline ``aws_iam_*_policy`` resources, and
* *trust policies* — the ``assume_role_policy`` on ``aws_iam_role``.

Both are parsed into statement lists by ``utils.policy.extract_statements``.
This module adds the IAM-specific predicates the rules share (action/resource
normalization, the write-action heuristic, MFA-condition and principal checks).
It registers no rules; it is imported by the ``iam_*`` rule modules.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.policy import extract_statements

IDENTITY_POLICY_TYPES = frozenset(
    {
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    }
)

INLINE_POLICY_TYPES = frozenset(
    {
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    }
)

ATTACHMENT_TYPES = frozenset(
    {
        "aws_iam_role_policy_attachment",
        "aws_iam_user_policy_attachment",
        "aws_iam_group_policy_attachment",
        "aws_iam_policy_attachment",
    }
)

_WRITE_VERBS = (
    "Put",
    "Create",
    "Delete",
    "Update",
    "Attach",
    "Detach",
    "Set",
    "Remove",
    "Write",
    "Modify",
    "Authorize",
    "Add",
)


def identity_statements(node: IaCNode) -> list[dict[str, Any]]:
    """Allow/Deny statements from an identity policy's ``policy`` attribute."""
    return extract_statements(node.attributes.get("policy", ""))


def trust_statements(node: IaCNode) -> list[dict[str, Any]]:
    """Statements from a role's ``assume_role_policy`` trust document."""
    return extract_statements(node.attributes.get("assume_role_policy", ""))


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def has_wildcard(values: list[Any]) -> bool:
    return any(str(v).strip() == "*" for v in values)


def is_write_action(action: str) -> bool:
    """Heuristic: an action naming a write/mutate verb (or a wildcard)."""
    if "*" in action:
        return True
    verb = action.split(":", 1)[-1]
    return any(verb.startswith(v) for v in _WRITE_VERBS)


def statement_enforces_mfa(stmt: dict[str, Any]) -> bool:
    """True if a statement's Condition requires MFA."""
    condition = stmt.get("Condition")
    if not isinstance(condition, dict):
        return False
    for checks in condition.values():
        if not isinstance(checks, dict):
            continue
        if any("multifactorauth" in str(k).lower() for k in checks):
            return True
    return False


def aws_principals(stmt: dict[str, Any]) -> list[str]:
    """The statement's AWS principal values (``"*"`` or ARNs)."""
    principal = stmt.get("Principal")
    if principal == "*":
        return ["*"]
    if isinstance(principal, dict):
        return [str(v) for v in as_list(principal.get("AWS"))]
    return []


def condition_keys(stmt: dict[str, Any]) -> set[str]:
    """All condition keys used by a statement (lower-cased), across operators."""
    condition = stmt.get("Condition")
    keys: set[str] = set()
    if isinstance(condition, dict):
        for checks in condition.values():
            if isinstance(checks, dict):
                keys.update(str(k).lower() for k in checks)
    return keys


def condition_has_wildcard_value(stmt: dict[str, Any]) -> bool:
    """True if any condition value is a bare ``*`` (non-restrictive)."""
    condition = stmt.get("Condition")
    if not isinstance(condition, dict):
        return False
    for checks in condition.values():
        if not isinstance(checks, dict):
            continue
        for value in checks.values():
            if any(str(v).strip() == "*" for v in as_list(value)):
                return True
    return False
