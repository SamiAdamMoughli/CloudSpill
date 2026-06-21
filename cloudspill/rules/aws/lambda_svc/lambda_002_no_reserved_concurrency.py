"""LAMBDA-002: Function has no reserved concurrency.

Without ``reserved_concurrent_executions``, a function draws from the account's
shared concurrency pool with no ceiling. A traffic spike or an attacker flooding
its trigger can scale it without bound — exhausting the regional concurrency
limit and starving every other function in the account (a noisy-neighbour DoS),
while also running up cost.

This is a resilience / cost control (LOW). The rule flags an
``aws_lambda_function`` with no ``reserved_concurrent_executions`` (or the
unreserved sentinel ``-1``).
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@register
class LambdaNoReservedConcurrency:
    """LAMBDA-002: reserved_concurrent_executions unset or -1."""

    rule_id = "LAMBDA-002"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_lambda_function":
            return []

        reserved = _to_int(node.attributes.get("reserved_concurrent_executions"))
        if reserved is not None and reserved >= 0:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Lambda function has no reserved concurrency",
                description=(
                    "reserved_concurrent_executions is not set on this "
                    "aws_lambda_function, so it can scale without bound from the "
                    "shared account pool. A flood can exhaust regional concurrency "
                    "and starve other functions."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set reserved_concurrent_executions to a ceiling appropriate "
                    "for the function so it cannot monopolise account concurrency."
                ),
                tags=frozenset(
                    {"lambda", "concurrency", "availability", "cost", "aws"}
                ),
            )
        ]
