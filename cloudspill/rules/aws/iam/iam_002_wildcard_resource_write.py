"""IAM-002: Policy grants write actions on a wildcard resource (Resource: "*").

An ``Allow`` statement with ``Resource: "*"`` and a write/mutate action lets the
principal create, modify, or delete *any* resource of that type across the whole
account — not just the ones it owns. That is the blast radius that turns a single
compromised principal into account-wide damage (data deletion, backdoor IAM,
resource hijack).

This rule flags an identity policy whose Allow statement combines a wildcard
resource with at least one write-like action.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.iam.policy_docs import (
    IDENTITY_POLICY_TYPES,
    as_list,
    has_wildcard,
    identity_statements,
    is_write_action,
)
from cloudspill.rules.base import register


@register
class IAMWildcardResourceWrite:
    """IAM-002: Allow with Resource "*" and a write action."""

    rule_id = "IAM-002"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in IDENTITY_POLICY_TYPES:
            return []

        for stmt in identity_statements(node):
            if stmt.get("Effect") != "Allow":
                continue
            resources = as_list(stmt.get("Resource"))
            actions = [str(a) for a in as_list(stmt.get("Action"))]
            if has_wildcard(resources) and any(is_write_action(a) for a in actions):
                return [self._finding(node)]
        return []

    def _finding(self, node: IaCNode) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="IAM policy grants write actions on a wildcard resource",
            description=(
                'An Allow statement combines Resource "*" with write/mutate '
                "actions, letting the principal change or delete any matching "
                "resource across the entire account."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Scope Resource to specific ARNs for write actions, or split read "
                "and write into separate, narrowly-scoped statements."
            ),
            tags=frozenset(
                {"iam", "wildcard-resource", "over-privilege", "blast-radius", "aws"}
            ),
        )
