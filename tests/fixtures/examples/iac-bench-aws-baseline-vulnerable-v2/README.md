# iac-bench-aws-baseline-vulnerable-v2

AWS Terraform benchmark stack for IaC SAST evaluation, generated from
the canonical `_base_framework` template.

## Naming

`iac-bench-<domain>-<scope>-<variant>-v<version>` — see
[CONTRIBUTING.md](../../../../../CONTRIBUTING.md#iac-bench-naming-convention).

- **domain:** aws
- **scope:** baseline
- **variant:** vulnerable
- **version:** v2

## Degraded control

| Toggle | Value | Expected finding |
|---|---|---|
| `data_restrict_kms_wildcards` | `false` | IAM-002 (HIGH) — KMS write action on Resource '*' |

Every other control is at its secure default, so a conforming scanner
reports **exactly one** finding for this stack.

## Scan

```bash
cloudspill .
```
