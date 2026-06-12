# iac-bench-aws-platform-vulnerable-v2

AWS Terraform benchmark stack for IaC SAST evaluation, generated from
the canonical `_base_framework` template.

## Naming

`iac-bench-<domain>-<scope>-<variant>-v<version>` — see
[CONTRIBUTING.md](../../../../../CONTRIBUTING.md#iac-bench-naming-convention).

- **domain:** aws
- **scope:** platform
- **variant:** vulnerable
- **version:** v2

## Degraded control

| Toggle | Value | Expected finding |
|---|---|---|
| `net_strict_tier_ingress` | `false` | EC2-002 (HIGH) — app tier ingress open to 0.0.0.0/0 |

Every other control is at its secure default, so a conforming scanner
reports **exactly one** finding for this stack.

## Scan

```bash
cloudspill .
```
