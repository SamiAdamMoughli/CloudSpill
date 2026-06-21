"""ECS-007: Container runs as root.

A container definition with no ``user`` field — or one set to ``root`` / uid
``0`` — runs its process as root inside the container. If an attacker breaks out
of the application into the container, starting as root makes privilege
escalation and host attacks far easier; running as an unprivileged user is a
cheap, high-value hardening step.

This rule flags a container whose ``user`` is unset, ``root``, ``0``, or
``0:0`` (root group).
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.ecs_fargate.containers import parse_container_definitions
from cloudspill.rules.base import register

_ROOT_USERS = frozenset({"", "root", "0", "0:0", "root:root"})


@register
class ECSRootUser:
    """ECS-007: a container definition runs as root."""

    rule_id = "ECS-007"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_ecs_task_definition":
            return []

        containers = parse_container_definitions(
            node.attributes.get("container_definitions")
        )
        for container in containers:
            user = str(container.get("user") or "").strip().lower()
            # uid before the ':' is what determines root
            if user.split(":", maxsplit=1)[0] in {"", "root", "0"}:
                return [self._finding(node, str(container.get("name", "?")), user)]
        return []

    def _finding(self, node: IaCNode, name: str, user: str) -> Finding:
        shown = user or "unset (defaults to root)"
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="ECS container runs as root",
            description=(
                f"Container '{name}' has user = {shown}, so its process runs as "
                "root inside the container. A breakout from the application then "
                "starts with root privileges, easing escalation and host attacks."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Set the container's `user` to a non-root uid[:gid] (and build the "
                "image with a matching unprivileged user)."
            ),
            tags=frozenset(
                {"ecs", "fargate", "root-user", "container-hardening", "aws"}
            ),
        )
