"""ECS-002: Container has no log configuration.

Each container should declare a ``logConfiguration`` (typically ``awslogs`` to
CloudWatch, or ``awsfirelens``) so its stdout/stderr is captured centrally.
Without it, container output stays on the host and is lost when the task stops —
leaving no record for debugging or, more importantly, for security
investigation of what a compromised container did.

This rule flags any container in an ``aws_ecs_task_definition`` that has no
``logConfiguration``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.ecs_fargate.containers import parse_container_definitions
from cloudspill.rules.base import register


@register
class ECSNoLogConfiguration:
    """ECS-002: a container definition has no logConfiguration."""

    rule_id = "ECS-002"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_ecs_task_definition":
            return []

        containers = parse_container_definitions(
            node.attributes.get("container_definitions")
        )
        for container in containers:
            if not container.get("logConfiguration"):
                return [self._finding(node, str(container.get("name", "?")))]
        return []

    def _finding(self, node: IaCNode, name: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="ECS container has no log configuration",
            description=(
                f"Container '{name}' declares no logConfiguration, so its "
                "stdout/stderr is not shipped anywhere. Output is lost when the "
                "task stops, leaving no audit trail for incident investigation."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Add a logConfiguration (e.g. logDriver = \"awslogs\" with the "
                "awslogs-group/region/stream-prefix options, or awsfirelens) to "
                "the container."
            ),
            tags=frozenset(
                {"ecs", "fargate", "logging", "observability", "aws"}
            ),
        )
