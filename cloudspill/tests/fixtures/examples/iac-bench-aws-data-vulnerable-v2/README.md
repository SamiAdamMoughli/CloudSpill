# iac-bench-aws-data-vulnerable-v2

AWS Terraform benchmark stack for IaC SAST evaluation, generated from
the canonical `_base_framework` template.

## Naming

`iac-bench-<domain>-<scope>-<variant>-v<version>` — see
[CONTRIBUTING.md](../../../../../CONTRIBUTING.md#iac-bench-naming-convention).

- **domain:** aws
- **scope:** data
- **variant:** vulnerable
- **version:** v2

## Degraded control

| Toggle | Value | Expected finding |
|---|---|---|
| `data_encrypt_volumes` | `false` | RDS-002 (HIGH) — storage encryption disabled |

Every other control is at its secure default, so a conforming scanner
reports **exactly one** finding for this stack.

## Scan

```bash
cloudspill .
```
