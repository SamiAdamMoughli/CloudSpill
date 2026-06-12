"""IAM security rules.

| ID      | Finding                                            | Severity |
|---------|----------------------------------------------------|----------|
| IAM-001 | Wildcard Action: "*" in policy                     | CRITICAL |
| IAM-002 | Wildcard Resource: "*" combined with write actions | HIGH     |
| IAM-003 | AdministratorAccess policy attached                | HIGH     |
| IAM-004 | MFA not enforced on policy                         | MEDIUM   |
| IAM-005 | Inline policy instead of managed policy            | LOW      |
"""

from __future__ import annotations

import json
from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_IAM_POLICY_TYPES = frozenset(
    {
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
    }
)

_ADMIN_POLICY_ARNS = frozenset(
    {
        "arn:aws:iam::aws:policy/AdministratorAccess",
        "arn:aws:iam::aws:policy/PowerUserAccess",
    }
)


def _as_statement_list(value: Any) -> list[dict[str, Any]]:
    """Coerce a policy ``Statement`` field to a list of statement dicts.

    A single statement may be written as one object rather than a list;
    anything that is not a dict is discarded.
    """
    items = value if isinstance(value, list) else [value]
    return [stmt for stmt in items if isinstance(stmt, dict)]


def _extract_policy_document(node: IaCNode) -> list[dict[str, Any]]:
    """Extract IAM policy statements from a node's attributes.

    Handles both inline JSON strings and pre-parsed dicts.
    Returns a list of statement dicts.
    """
    policy_raw = node.attributes.get("policy", "")

    if isinstance(policy_raw, dict):
        return _as_statement_list(policy_raw.get("Statement", []))

    if isinstance(policy_raw, str):
        # Strip heredoc markers (<<EOF, <<-EOF) and trailing EOF
        cleaned = policy_raw.strip()
        if cleaned.startswith("<<"):
            first_newline = cleaned.index("\n") if "\n" in cleaned else len(cleaned)
            cleaned = cleaned[first_newline + 1 :]
            # Remove trailing heredoc marker
            lines = cleaned.rsplit("\n", 1)
            if len(lines) == 2 and lines[1].strip().isalpha():
                cleaned = lines[0]
            cleaned = cleaned.strip()

        if cleaned.startswith("{"):
            try:
                doc = json.loads(cleaned)
                return _as_statement_list(doc.get("Statement", []))
            except (json.JSONDecodeError, AttributeError):
                return []

    return []


def _get_actions(statement: dict[str, Any]) -> list[str]:
    """Normalize Action field to a list."""
    action = statement.get("Action", [])
    if isinstance(action, str):
        return [action]
    return list(action)


def _get_resources(statement: dict[str, Any]) -> list[str]:
    """Normalize Resource field to a list."""
    resource = statement.get("Resource", [])
    if isinstance(resource, str):
        return [resource]
    return list(resource)


def _is_write_action(action: str) -> bool:
    """Heuristic: actions containing write-like verbs."""
    write_verbs = {
        "Put",
        "Create",
        "Delete",
        "Update",
        "Attach",
        "Detach",
        "Set",
        "Remove",
    }
    return any(verb in action for verb in write_verbs)


@register
class IAMWildcardAction:
    """IAM-001: Wildcard Action: '*' in policy."""

    rule_id = "IAM-001"
    severity = Severity.CRITICAL

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _IAM_POLICY_TYPES:
            return []

        statements = _extract_policy_document(node)
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = _get_actions(stmt)
            if "*" in actions:
                return [
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title="Wildcard action in policy",
                        description="Policy grants Action: '*', allowing all AWS API actions.",
                        resource=node.node_id,
                        file=node.source_file,
                        line=node.line,
                    )
                ]
        return []


@register
class IAMWildcardResource:
    """IAM-002: Wildcard Resource '*' combined with write actions."""

    rule_id = "IAM-002"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _IAM_POLICY_TYPES:
            return []

        statements = _extract_policy_document(node)
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            resources = _get_resources(stmt)
            actions = _get_actions(stmt)
            if "*" in resources and any(_is_write_action(a) for a in actions):
                return [
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title="Wildcard resource with write actions",
                        description="Policy grants write actions on Resource: '*', affecting all resources in the account.",
                        resource=node.node_id,
                        file=node.source_file,
                        line=node.line,
                    )
                ]
        return []


@register
class IAMAdminAccess:
    """IAM-003: AdministratorAccess policy attached."""

    rule_id = "IAM-003"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in {
            "aws_iam_role_policy_attachment",
            "aws_iam_user_policy_attachment",
            "aws_iam_group_policy_attachment",
            "aws_iam_policy_attachment",
        }:
            return []

        policy_arn = node.attributes.get("policy_arn", "")
        if policy_arn in _ADMIN_POLICY_ARNS:
            return [
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title="AdministratorAccess policy attached",
                    description=f"Policy '{policy_arn}' grants full administrative access to the AWS account.",
                    resource=node.node_id,
                    file=node.source_file,
                    line=node.line,
                )
            ]
        return []


@register
class IAMNoMFA:
    """IAM-004: MFA not enforced in policy condition."""

    rule_id = "IAM-004"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _IAM_POLICY_TYPES:
            return []

        statements = _extract_policy_document(node)
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            condition = stmt.get("Condition", {})
            # Check if MFA is enforced anywhere in the condition
            mfa_enforced = self._has_mfa_condition(condition)
            if not mfa_enforced:
                return [
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title="MFA not enforced on policy",
                        description="Allow statement has no MFA condition. Compromised credentials grant immediate access.",
                        resource=node.node_id,
                        file=node.source_file,
                        line=node.line,
                    )
                ]
        return []

    @staticmethod
    def _has_mfa_condition(condition: dict[str, Any]) -> bool:
        """Check if any condition block enforces MFA."""
        for checks in condition.values():
            if isinstance(checks, dict):
                for key in checks:
                    if "MultiFactorAuth" in key or "mfa" in key.lower():
                        return True
        return False


@register
class IAMInlinePolicy:
    """IAM-005: Inline policy instead of managed policy."""

    rule_id = "IAM-005"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in {
            "aws_iam_role_policy",
            "aws_iam_user_policy",
            "aws_iam_group_policy",
        }:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Inline policy instead of managed policy",
                description="Inline policies are harder to audit and reuse. Prefer managed policies.",
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
            )
        ]
