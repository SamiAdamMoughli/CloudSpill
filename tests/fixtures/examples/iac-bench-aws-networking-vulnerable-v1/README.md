# iac-bench-aws-networking-vulnerable-v1

AWS Terraform benchmark stack for IaC SAST evaluation, generated from
the canonical `_base_framework` template.

## Naming

`iac-bench-<domain>-<scope>-<variant>-v<version>` — see
[CONTRIBUTING.md](../../../../../CONTRIBUTING.md#iac-bench-naming-convention).

- **domain:** aws
- **scope:** networking
- **variant:** vulnerable
- **version:** v1

## Degraded control

| Toggle | Value | Expected finding |
|---|---|---|
| `net_restrict_public_management` | `false` | EC2-001 (CRITICAL) — SSH open to 0.0.0.0/0 |

Every other control is at its secure default, so a conforming scanner
reports **exactly one** finding for this stack.

## Scan

```bash
cloudspill .
```
