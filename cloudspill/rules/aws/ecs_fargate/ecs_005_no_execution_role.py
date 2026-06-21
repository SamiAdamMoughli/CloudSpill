"""ECS-005: Task definition has no execution role.

The *execution role* (``execution_role_arn``) is the identity the ECS agent
itself uses — to pull images from ECR, fetch ``secrets`` from Secrets
Manager/SSM, and ship container logs to CloudWatch. Without it, a task cannot
resolve secrets into the container at launch, which pushes teams toward plaintext
environment variables (see ECS-006), and cannot pull private images or deliver
logs.

(Distinct from the *task role* in ECS-003, which is for the application's own
AWS calls.)

This rule flags an ``aws_ecs_task_definition`` with no ``execution_role_arn``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class ECSNoExecutionRole:
    """ECS-005: aws_ecs_task_definition has no execution_role_arn."""

    rule_id = "ECS-005"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_ecs_task_definition":
            return []

        if str(node.attributes.get("execution_role_arn", "")).strip():
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="ECS task definition has no execution role",
                description=(
                    "execution_role_arn is not set on this aws_ecs_task_definition. "
                    "The ECS agent cannot fetch secrets into the container, pull "
                    "private ECR images, or deliver logs — which pushes teams "
                    "toward plaintext environment secrets."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set execution_role_arn to a role with the "
                    "AmazonECSTaskExecutionRolePolicy permissions plus access to "
                    "the specific secrets the task needs."
                ),
                tags=frozenset({"ecs", "fargate", "iam", "execution-role", "aws"}),
            )
        ]
