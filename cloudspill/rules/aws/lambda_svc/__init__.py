"""AWS Lambda security rules.

Targets aws_lambda_function (LAMBDA-010 also walks to its aws_iam_role).

Enable with: --rules lambda

| ID         | Resource type          | Finding                                       | Severity |
|------------|------------------------|-----------------------------------------------|----------|
| LAMBDA-001 | aws_lambda_function    | Execution timeout above 300s                  | LOW      |
| LAMBDA-002 | aws_lambda_function    | No reserved concurrency                       | LOW      |
| LAMBDA-003 | aws_lambda_function    | Secret in a plaintext environment variable    | HIGH     |
| LAMBDA-004 | aws_lambda_function    | Not attached to a VPC                         | LOW      |
| LAMBDA-005 | aws_lambda_function    | No dead-letter queue                          | LOW      |
| LAMBDA-006 | aws_lambda_function    | Versions not published                        | LOW      |
| LAMBDA-007 | aws_lambda_function    | X-Ray tracing not Active                      | LOW      |
| LAMBDA-008 | aws_lambda_function    | Code signing not enforced                     | MEDIUM   |
| LAMBDA-009 | aws_lambda_function    | No explicit logging configuration             | LOW      |
| LAMBDA-010 | aws_lambda_function    | Execution role grants wildcard admin          | HIGH     |

Rules are auto-discovered via @register; no manual imports needed here.
"""
