"""AWS KMS security rules.

Enable with: --rules kms

| ID       | Resource type    | Finding                                        | Severity |
|----------|------------------|------------------------------------------------|----------|
| KMS-001  | aws_kms_key      | Key policy allows wildcard principal to use key | HIGH    |
| KMS-002  | aws_kms_key      | Symmetric CMK rotation not enabled             | MEDIUM   |
| KMS-003  | aws_kms_grant    | Grant has no encryption-context constraints    | MEDIUM   |
| KMS-004  | aws_kms_key      | Deletion window shorter than 30 days           | LOW      |

Rules are auto-discovered via @register; no manual imports needed here.
"""
