"""ECS-006: Secret passed through a plaintext environment variable.

A container's ``environment`` entries are plaintext: they are stored in the task
definition, visible in the console and ``describe-task-definition``, and exposed
to anyone who can read the metadata endpoint. Passing a password, API key, or
token this way leaks it. ECS provides ``secrets`` for exactly this — values are
pulled from Secrets Manager / SSM Parameter Store at launch and never stored in
the definition.

This rule flags a container whose ``environment`` has a variable whose **name**
looks secret-bearing (password, secret, token, api key, access/private key,
etc.) and which carries an inline value.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.ecs_fargate.containers import parse_container_definitions
from cloudspill.rules.base import register

_SECRET_HINTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "access_key",
    "accesskey",
    "private_key",
    "privatekey",
    "credential",
)


def _looks_secret(name: str) -> bool:
    lowered = name.replace("-", "_").lower()
    return any(hint in lowered for hint in _SECRET_HINTS)


@register
class ECSSecretsInEnvVars:
    """ECS-006: a container environment variable carries an inline secret."""

    rule_id = "ECS-006"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_ecs_task_definition":
            return []

        containers = parse_container_definitions(
            node.attributes.get("container_definitions")
        )
        for container in containers:
            env = container.get("environment")
            if not isinstance(env, list):
                continue
            for var in env:
                if not isinstance(var, dict):
                    continue
                name = str(var.get("name", ""))
                value = var.get("value")
                if _looks_secret(name) and value not in (None, ""):
                    return [self._finding(node, str(container.get("name", "?")), name)]
        return []

    def _finding(self, node: IaCNode, container: str, var_name: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Secret passed through a plaintext environment variable",
            description=(
                f"Container '{container}' sets environment variable '{var_name}' "
                "with an inline value. Plaintext environment variables are stored "
                "in the task definition and exposed via the console, API, and "
                "metadata endpoint."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Move the value into Secrets Manager or SSM Parameter Store and "
                "reference it through the container's `secrets` block instead of "
                "`environment`."
            ),
            tags=frozenset(
                {"ecs", "fargate", "secrets", "plaintext-credentials", "aws"}
            ),
        )
