"""LAMBDA-009: Function has no explicit logging configuration.

The ``logging_config`` block controls how a function logs — structured JSON vs
plain text (``log_format``), the minimum ``application_log_level`` /
``system_log_level``, and the destination ``log_group``. Relying on the implicit
default means logs are unstructured, capture every level (or none, if the role
lacks permissions), and land in an auto-created group with no managed retention —
weak ground for both debugging and security investigation.

This is an observability hygiene control (LOW). The rule flags an
``aws_lambda_function`` with no ``logging_config`` block.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register


@register
class LambdaLoggingNotConfigured:
    """LAMBDA-009: aws_lambda_function has no logging_config block."""

    rule_id = "LAMBDA-009"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_lambda_function":
            return []

        blocks = as_blocks(node.attributes.get("logging_config"))
        blocks += [c.attributes for c in node.children if c.resource_type == "logging_config"]
        if blocks:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Lambda function has no explicit logging configuration",
                description=(
                    "This aws_lambda_function has no logging_config block, so it "
                    "uses default unstructured logging with no controlled log "
                    "format, level, or destination group — weakening debugging and "
                    "security investigation."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Add a logging_config block setting log_format (JSON), "
                    "application_log_level, and an explicit log_group with managed "
                    "retention."
                ),
                tags=frozenset(
                    {"lambda", "logging", "observability", "aws"}
                ),
            )
        ]
