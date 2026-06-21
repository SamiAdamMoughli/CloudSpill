"""ECS-004: Task / container has no memory limit.

Without a memory limit, a single container can consume all memory on the host
(or, on Fargate, hit task-level limits unpredictably), starving every other
container and turning one buggy or attacker-driven workload into a
denial-of-service for its neighbours. A limit is set either at the task level
(``memory`` on ``aws_ecs_task_definition``, required for Fargate) or per
container (``memory`` / ``memoryReservation``).

This rule flags a task definition that sets no task-level ``memory`` *and* has
at least one container with no memory limit of its own.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.ecs_fargate.containers import parse_container_definitions
from cloudspill.rules.base import register


def _has_value(value: Any) -> bool:
    return value is not None and str(value).strip() not in ("", "0")


@register
class ECSNoResourceLimits:
    """ECS-004: no task-level memory and a container without a memory limit."""

    rule_id = "ECS-004"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_ecs_task_definition":
            return []

        if _has_value(node.attributes.get("memory")):
            return []  # task-level memory limit covers all containers

        containers = parse_container_definitions(
            node.attributes.get("container_definitions")
        )
        for container in containers:
            if not _has_value(container.get("memory")) and not _has_value(
                container.get("memoryReservation")
            ):
                return [self._finding(node, str(container.get("name", "?")))]
        return []

    def _finding(self, node: IaCNode, name: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="ECS task has no memory limit",
            description=(
                f"This task definition sets no task-level memory and container "
                f"'{name}' sets neither memory nor memoryReservation. The "
                "container can exhaust host memory and starve other workloads "
                "(resource-exhaustion DoS)."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Set a task-level memory value, or a per-container memory / "
                "memoryReservation limit, sized to the workload."
            ),
            tags=frozenset(
                {"ecs", "fargate", "resource-limits", "availability", "aws"}
            ),
        )
