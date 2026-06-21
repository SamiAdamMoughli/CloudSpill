"""LAMBDA-006: Function does not publish versions.

With ``publish = true`` each deployment creates an immutable, numbered version.
Versions give you a known-good artifact to roll back to, let aliases shift
traffic deliberately, and provide an audit trail of exactly what code ran when.
Without versioning every change mutates ``$LATEST`` in place, so there is no
rollback point and no record of prior code — bad for both reliability and
incident forensics.

This is a resilience / change-management control (LOW). The rule flags an
``aws_lambda_function`` whose ``publish`` is not true.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


def _is_true(value: object) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() == "true"


@register
class LambdaUnversioned:
    """LAMBDA-006: aws_lambda_function has publish not true."""

    rule_id = "LAMBDA-006"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_lambda_function":
            return []

        if _is_true(node.attributes.get("publish")):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Lambda function does not publish versions",
                description=(
                    "publish is not true on this aws_lambda_function, so every "
                    "change mutates $LATEST in place. There is no immutable version "
                    "to roll back to and no audit trail of prior code."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set publish = true so each deployment creates an immutable, "
                    "numbered version usable with aliases and rollback."
                ),
                tags=frozenset(
                    {"lambda", "versioning", "rollback", "change-management", "aws"}
                ),
            )
        ]
