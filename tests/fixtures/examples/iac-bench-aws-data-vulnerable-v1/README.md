# iac-bench-aws-data-vulnerable-v1

AWS Terraform benchmark stack for IaC SAST evaluation, generated from
the canonical `_base_framework` template.

## Naming

`iac-bench-<domain>-<scope>-<variant>-v<version>` — see
[CONTRIBUTING.md](../../../../../CONTRIBUTING.md#iac-bench-naming-convention).

- **domain:** aws
- **scope:** data
- **variant:** vulnerable
- **version:** v1

## Degraded control

| Toggle | Value | Expected finding |
|---|---|---|
| `net_enable_subnet_isolation` | `false` | EC2-004 (MEDIUM) — instance assigned a public IP |

Every other control is at its secure default, so a conforming scanner
reports **exactly one** finding for this stack.

## Scan

```bash
cloudspill .
```
