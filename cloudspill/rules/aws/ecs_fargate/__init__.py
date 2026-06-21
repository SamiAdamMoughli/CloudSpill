"""AWS ECS / Fargate / ECR security rules.

Covers container image scanning (ECR) and ECS task-definition hardening. The
ECS rules parse the task definition's ``container_definitions`` JSON via the
shared ``containers.parse_container_definitions`` helper.

Enable with: --rules ecs,ecr

| ID       | Resource type             | Finding                                       | Severity |
|----------|---------------------------|-----------------------------------------------|----------|
| ECR-001  | aws_ecr_repository        | Image scan-on-push disabled                   | MEDIUM   |
| ECS-001  | aws_ecs_task_definition   | Privileged container                          | HIGH     |
| ECS-002  | aws_ecs_task_definition   | Container has no log configuration            | LOW      |
| ECS-003  | aws_ecs_task_definition   | No task role (task_role_arn)                   | LOW      |
| ECS-004  | aws_ecs_task_definition   | No memory limit (task or container)           | LOW      |
| ECS-005  | aws_ecs_task_definition   | No execution role (execution_role_arn)        | MEDIUM   |
| ECS-006  | aws_ecs_task_definition   | Secret in a plaintext environment variable    | HIGH     |
| ECS-007  | aws_ecs_task_definition   | Container runs as root                        | MEDIUM   |
| ECS-008  | aws_ecs_task_definition   | Container binds a static host port            | LOW      |

Rules are auto-discovered via @register; no manual imports needed here.
"""
