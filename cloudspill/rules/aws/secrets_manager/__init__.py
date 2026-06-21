"""AWS Secrets Manager security rules.

Covers secret encryption, rotation, and resource-policy exposure. SECRETS-001
and SECRETS-004 use the resource graph to find the rotation / policy resources
attached to a secret.

Enable with: --rules secrets

| ID           | Resource type                          | Finding                                  | Severity |
|--------------|----------------------------------------|------------------------------------------|----------|
| SECRETS-001  | aws_secretsmanager_secret              | No automatic rotation configured         | MEDIUM   |
| SECRETS-002  | aws_secretsmanager_secret              | Not encrypted with a customer-managed CMK | MEDIUM  |
| SECRETS-003  | aws_secretsmanager_secret_policy       | Broad cross-account / wildcard access    | HIGH     |
| SECRETS-004  | aws_secretsmanager_secret              | No resource-based policy                  | LOW      |
| SECRETS-005  | aws_secretsmanager_secret_rotation     | Rotation interval longer than 90 days    | LOW      |

Rules are auto-discovered via @register; no manual imports needed here.
"""
