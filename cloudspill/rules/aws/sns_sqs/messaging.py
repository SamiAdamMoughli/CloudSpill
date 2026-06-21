"""Shared helpers for the SNS/SQS rule set.

SNS-001 and SQS-001 ask the same question of two different resource policies:
does an ``Allow`` statement grant a wildcard principal with no constraining
``Condition``? This helper centralizes that check. It registers no rules; it is
imported by the ``sns_*`` / ``sqs_*`` rule modules.
"""

from __future__ import annotations

from typing import Any

from cloudspill.rules.aws.utils.policy import extract_statements, is_wildcard_principal


def policy_allows_public(policy_raw: Any) -> bool:
    """True if the policy has an Allow + wildcard principal + no Condition."""
    for stmt in extract_statements(policy_raw):
        if stmt.get("Effect") != "Allow" or stmt.get("Condition"):
            continue
        if is_wildcard_principal(stmt.get("Principal")):
            return True
    return False
