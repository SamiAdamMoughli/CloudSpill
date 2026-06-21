"""ECS-001: Task definition runs a privileged container.

A container definition with ``"privileged": true`` runs with full host-level
capabilities — effectively root on the underlying instance, able to access
devices and escape isolation. It is almost never required, and on Fargate it is
not even supported, so its presence is a strong signal of an over-powered or
copy-pasted task.

This rule flags any container in an ``aws_ecs_task_definition`` whose
``privileged`` flag is true.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.ecs_fargate.containers import parse_container_definitions
from cloudspill.rules.base import register


def _is_true(value: object) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() == "true"


@register
class ECSPrivilegedContainer:
    """ECS-001: a container definition sets privileged = true."""

    rule_id = "ECS-001"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_ecs_task_definition":
            return []

        containers = parse_container_definitions(
            node.attributes.get("container_definitions")
        )
        for container in containers:
            if _is_true(container.get("privileged")):
                return [self._finding(node, str(container.get("name", "?")))]
        return []

    def _finding(self, node: IaCNode, name: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="ECS task runs a privileged container",
            description=(
                f"Container '{name}' sets privileged = true, granting host-level "
                "capabilities equivalent to root on the underlying host. A "
                "compromise of this container can break isolation and take over "
                "the host."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Remove privileged (set it false) and grant only the specific "
                "Linux capabilities the workload needs via linuxParameters."
            ),
            tags=frozenset(
                {"ecs", "fargate", "privileged", "container-escape", "aws"}
            ),
        )
