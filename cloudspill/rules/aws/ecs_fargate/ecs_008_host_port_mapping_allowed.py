"""ECS-008: Container binds a static host port.

A ``portMappings`` entry with an explicit, non-zero ``hostPort`` pins the
container to a fixed port on the host's network. In ``bridge``/``host`` network
mode this exposes the service directly on the host, bypasses dynamic port
mapping, blocks running multiple task copies on one host, and widens the host's
network exposure. Leaving ``hostPort`` unset (or 0) lets ECS assign an ephemeral
port; ``awsvpc``/Fargate gives each task its own ENI and does not need it.

This rule flags a container with a portMapping whose ``hostPort`` is set to a
non-zero value different from the ``containerPort``.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.ecs_fargate.containers import parse_container_definitions
from cloudspill.rules.base import register


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@register
class ECSHostPortMapping:
    """ECS-008: a container portMapping binds a static host port."""

    rule_id = "ECS-008"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_ecs_task_definition":
            return []

        containers = parse_container_definitions(
            node.attributes.get("container_definitions")
        )
        for container in containers:
            mappings = container.get("portMappings")
            if not isinstance(mappings, list):
                continue
            for mapping in mappings:
                if not isinstance(mapping, dict):
                    continue
                host_port = _to_int(mapping.get("hostPort"))
                container_port = _to_int(mapping.get("containerPort"))
                if host_port not in (None, 0) and host_port != container_port:
                    return [
                        self._finding(
                            node, str(container.get("name", "?")), host_port
                        )
                    ]
        return []

    def _finding(self, node: IaCNode, name: str, host_port: int) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="ECS container binds a static host port",
            description=(
                f"Container '{name}' maps a static hostPort {host_port}. This pins "
                "the service to a fixed port on the host, exposing it directly and "
                "preventing dynamic port mapping or multiple task copies per host."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Leave hostPort unset (or 0) for dynamic mapping, or move the task "
                "to awsvpc/Fargate networking where each task gets its own ENI."
            ),
            tags=frozenset(
                {"ecs", "fargate", "networking", "host-port", "aws"}
            ),
        )
