"""ECS-003: Task definition has no task role.

The *task role* (``task_role_arn``) is the IAM identity the application code in
the containers assumes to call AWS APIs. Without it, teams commonly fall back to
baking long-lived access keys into the image or environment instead of using
short-lived, scoped role credentials delivered through the task metadata
endpoint.

(Note this is distinct from the *execution role* in ECS-005, which is what the
ECS agent uses to pull images and fetch secrets.)

This rule flags an ``aws_ecs_task_definition`` with no ``task_role_arn``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class ECSNoTaskRole:
    """ECS-003: aws_ecs_task_definition has no task_role_arn."""

    rule_id = "ECS-003"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_ecs_task_definition":
            return []

        if str(node.attributes.get("task_role_arn", "")).strip():
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="ECS task definition has no task role",
                description=(
                    "task_role_arn is not set on this aws_ecs_task_definition, so "
                    "the application has no IAM identity for AWS API calls. This "
                    "encourages baking long-lived credentials into the image "
                    "instead of using short-lived task-role credentials."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set task_role_arn to a least-privilege IAM role so the "
                    "application receives scoped, short-lived credentials."
                ),
                tags=frozenset(
                    {"ecs", "fargate", "iam", "task-role", "aws"}
                ),
            )
        ]
