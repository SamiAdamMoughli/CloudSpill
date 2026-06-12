# iac-bench-aws-platform-vulnerable-v3

AWS Terraform benchmark stack for IaC SAST evaluation, generated from
the canonical `_base_framework` template.

## Naming

`iac-bench-<domain>-<scope>-<variant>-v<version>` — see
[CONTRIBUTING.md](../../../../../CONTRIBUTING.md#iac-bench-naming-convention).

- **domain:** aws
- **scope:** platform
- **variant:** vulnerable
- **version:** v3

## Degraded control

| Toggle | Value | Expected finding |
|---|---|---|
| `data_secure_bucket_policy` | `false` | S3-001 (CRITICAL) — bucket ACL public-read |

Every other control is at its secure default, so a conforming scanner
reports **exactly one** finding for this stack.

## Scan

```bash
cloudspill .
```
