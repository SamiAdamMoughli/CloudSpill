# Contributing to CloudSpill

## Adding a New Rule

1. Create a class in `cloudspill/rules/<category>.py` implementing the `Rule` protocol.
2. The class must expose `rule_id: str`, `severity: Severity`, and `check(node, graph) -> list[Finding]`.
3. Register it in `cloudspill/rules/__init__.py` inside `RuleRegistry._discover()`.
4. Add test cases in `tests/test_rules.py` with a fixture `.tf` or `Dockerfile` in `tests/fixtures/`.

## Adding a New Parser

1. Create a class in `cloudspill/parsers/` implementing the `Parser` protocol.
2. Add it to the parser list in `cloudspill/parsers/registry.py`.
3. Add fixture files and tests in `tests/`.

## Adding a New Output Format

1. Create a class in `cloudspill/output/` implementing the `Formatter` protocol.
2. Wire it into the CLI dispatch in `cloudspill/cli.py`.

## iac-bench Naming Convention

All benchmark fixture stacks under `tests/fixtures/examples/` follow
a deterministic, machine-parseable naming scheme so the dataset is reproducible,
versionable, and filterable — and never confusable with real production systems.

### Canonical format

```
iac-bench-<domain>-<scope>-<variant>-v<version>
```

| Field | Required | Values |
|---|---|---|
| `iac-bench` | yes | Fixed prefix for every stack. |
| `<domain>` | yes | `aws`, `multi-cloud`, `k8s`, `terraform`, `serverless`, `hybrid` |
| `<scope>` | yes | `networking`, `multitier`, `compute`, `data`, `fullstack`, `platform`, `edge`, `baseline` |
| `<variant>` | recommended | `secure`, `mixed` (default), `vulnerable`, `minimal`, `enterprise` |
| `v<version>` | yes | `v1`, `v2`, `v3` (extended `v1.0`/`v1.1` permitted) |

Each stack also carries the canonical metadata tag block on every resource via
`local.tags`: `Project`, `Domain`, `Scope`, `Variant`, `Version`, `ManagedBy`.

### Examples

```
iac-bench-aws-multitier-mixed-v1        # default benchmark stack
iac-bench-aws-fullstack-secure-v1       # compliant baseline
iac-bench-aws-networking-vulnerable-v2  # vulnerability-heavy
iac-bench-terraform-baseline-minimal-v1 # minimal reproducible
iac-bench-aws-platform-enterprise-v1    # large-scale simulation
```

## Adding a Benchmark Case

The `vulnerable` stacks are **generated**, not hand-written. CloudSpill is a
static HCL reader — it does not resolve `module` blocks or evaluate
`var.*`/conditionals/`terraform.tfvars` — so a "secure module + one tfvars
toggle" design would produce zero findings. Instead the parameterization lives
at generation time:

- `tests/fixtures/examples/_base_framework/render.py` holds one
  canonical, secure-by-default baseline plus the case manifest (`CASES`).
- Each case renders a fully self-contained, deployable stack that is secure
  everywhere except the single control it targets, which is baked in as a
  **literal** misconfiguration the scanner can see.
- The degraded control is still declared as a real (secure-default) variable and
  set in the case's `terraform.tfvars`, preserving "exactly one toggle isolates
  the case" while keeping valid `terraform validate`-able HCL.

Each stack must produce **exactly one finding**. To add a case:

1. Add an entry to `CASES` in `render.py` (dirname, `scope`, `version`,
   `toggle`, `value`, `vuln`, `expects`).
2. If the control needs a new literal misconfiguration, extend the relevant
   `*_tf()` builder to branch on the `vuln` key.
3. Regenerate and verify a single matching finding:

   ```bash
   python tests/fixtures/examples/_base_framework/render.py
   cloudspill tests/fixtures/examples/<your-case> --format json
   ```

## Quality Gates

All contributions must pass:

- `mypy --strict`
- `pylint` score ≥ 9.0
- `bandit` clean
- `pytest` passing
- `black` + `isort` formatted