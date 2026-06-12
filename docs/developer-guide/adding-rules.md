# Adding a New Rule

This guide covers the full process of adding a security rule to CloudSpill —
not just writing the rule class, but every place in the codebase you need to
touch (and the places you *don't*).

## TL;DR checklist

For a brand-new rule in an **existing** service (e.g. another S3 rule):

- [ ] Create the rule file under `cloudspill/rules/<cloud>/<service>/<id>_<slug>.py`
- [ ] Decorate the rule class with `@register`
- [ ] Give it a `rule_id` whose prefix matches the service category (e.g. `S3-014`)
- [ ] Add a row to the service `__init__.py` rule table
- [ ] Add a vulnerable + clean fixture and a test in `tests/`
- [ ] Run `pytest` and a manual scan to confirm it fires exactly once

For a brand-new **service or cloud**, also:

- [ ] Create the package directory **with an `__init__.py`** (and parent dirs too)
- [ ] Add the new category to `_RULE_CHOICES` in `cloudspill/cli.py`
- [ ] Update the rule count / coverage list in `README.md`

> ⚠️ **The most common mistake:** forgetting an `__init__.py`. Rule discovery
> walks packages with `pkgutil.walk_packages`, which only descends into
> directories that are real Python packages. A missing `__init__.py` anywhere
> in the path (e.g. `rules/aws/__init__.py`) silently hides *every* rule
> beneath it. See [Rule discovery](#how-rule-discovery-works).

---

## 1. Where rules live

```
cloudspill/rules/
├── __init__.py          # RuleRegistry — auto-discovery, no edits needed per rule
├── base.py              # @register decorator + Rule protocol
├── aws/
│   ├── __init__.py      # REQUIRED package marker
│   ├── s3/
│   │   ├── __init__.py  # service docstring + rule table
│   │   ├── s3_001_public_acl.py
│   │   └── ...
│   └── api_gateway/
│       └── ...
├── azure/
│   └── ...
└── docker/
    └── ...
```

One rule per file. The filename uses lowercase with an underscore-separated
numeric id and a short slug: `apigw_001_no_authorization.py`.

## 2. The rule ID convention (this matters for filtering)

A rule's `rule_id` looks like `APIGW-001`, `S3-014`, `AZ-STG-003`.

`RuleRegistry` derives the **category** used by `--rules` from the ID:

```python
# cloudspill/rules/__init__.py
@staticmethod
def _rule_category(rule_id: str) -> str:
    return rule_id.split("-")[0].lower()   # "S3-014" -> "s3"
```

So:

- `--rules s3` enables every rule whose ID starts with `S3-`.
- The **filename** uses an underscore (`s3_014_...`); the **`rule_id`** uses a
  hyphen (`S3-014`). Keep these consistent in number, not in punctuation.
- Pick the prefix deliberately: it *is* the user-facing filter name.

## 3. Writing the rule class

A rule is any class with `rule_id`, `severity`, and a `check()` method,
decorated with `@register`. It satisfies the `Rule` protocol in
[`base.py`](../../cloudspill/rules/base.py) structurally — no base class to
inherit.

```python
"""APIGW-007: Example — short description of what this catches and why."""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class APIGatewayExample:
    """APIGW-007: One-line summary."""

    rule_id = "APIGW-007"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        # 1. Bail out fast on irrelevant nodes.
        if node.resource_type != "aws_api_gateway_method":
            return []

        # 2. Inspect attributes. Coerce types defensively — hcl2 may give you
        #    a str, a list, a dict, or a bool depending on how it was written.
        if node.attributes.get("some_flag") is not True:
            return []

        # 3. Return a finding (or several). Empty list == node is clean.
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Short, specific finding title",
                description="What is wrong and what the impact is.",
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation="The concrete fix (e.g. set X = true).",
                tags=frozenset({"api-gateway", "aws", "public-access"}),
            )
        ]
```

### `check()` contract

- Called **once per node** in the graph. Filter by `node.resource_type` first.
- Return `[]` for a clean node; return one `Finding` per distinct violation.
- The `graph` argument lets you reason across resources — use
  `graph.outgoing(node.node_id)` / `graph.incoming(node.node_id)` and
  `graph.get_node(id)` for reference-following rules (see `EC2`/`AZ-VM-002`
  for graph-traversal examples). The parameter is part of the protocol even
  when a rule doesn't use it.

### Defensive attribute access

`python-hcl2` is inconsistent about singleton blocks. A nested block may arrive
as a `dict` *or* a single-element `list[dict]`, and inline blocks may instead
appear as `node.children`. Normalize before inspecting:

```python
metadata = node.attributes.get("metadata_options", {})
for block in (metadata if isinstance(metadata, list) else [metadata]):
    ...
# and/or check children:
for child in node.children:
    if child.resource_type == "metadata_options":
        ...
```

### The `Finding` fields

Required: `rule_id`, `severity`, `title`, `description`, `resource`, `file`,
`line`. Optional but strongly encouraged: `remediation` (actionable fix),
`tags` (a `frozenset` of categories / compliance refs), `references` (a tuple
of doc URLs). See [`findings.py`](../../cloudspill/models/findings.py).

## 4. Update the service `__init__.py` table

Each service package keeps a Markdown table of its rules in the module
docstring. Add your row so the package stays self-documenting:

```python
"""AWS API Gateway security rules.

Enable with: --rules apigw

| ID         | Resource type            | Finding                    | Severity |
|------------|--------------------------|----------------------------|----------|
| APIGW-001  | aws_api_gateway_method   | Method has no authorization| HIGH     |
| APIGW-007  | aws_api_gateway_method   | <your new finding>         | HIGH     |
"""
```

You do **not** import the rule module anywhere — discovery is automatic.

## 5. Do you need to touch the parser? (Usually no.)

The Terraform and Docker parsers are **generic**. Any `resource` / `data`
block becomes an `IaCNode` with `resource_type` set to the raw type string —
there is no per-resource-type registration. A rule for a brand-new resource
type works without parser changes.

Touch the parser **only** if:

- You need an attribute the parser currently drops or mangles (check
  `_clean_attributes` / `_extract_children` in
  [`parsers/terraform.py`](../../cloudspill/parsers/terraform.py)).
- You're adding a whole new **file format** (not just a new resource). That is
  a parser plus a registration in `parsers/registry.py`, out of scope here.

## 6. How rule discovery works

`RuleRegistry._discover()` does:

```python
for _, name, _ in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
    if not name.endswith(".base"):
        importlib.import_module(name)
```

Importing each module runs its `@register` decorators, which append to a
module-level list read by `get_registered_rules()`.

**Consequences:**

- Every directory in the path must contain an `__init__.py`, or
  `walk_packages` won't descend into it and the rules below are invisible.
  Newly created service/cloud directories are the usual culprit.
- No central list of rules to maintain — adding a file is zero-config *given*
  the package markers exist.

## 7. Register the category in the CLI (new services/clouds only)

`--rules` does **not** validate against a fixed list — it's a free
comma-split, so a new category filters correctly the moment its rules exist.
But the `--help` text comes from a constant, so add new categories there for
discoverability:

```python
# cloudspill/cli.py
_RULE_CHOICES = "s3,iam,ec2,rds,docker,az,apigw"   # add your category
```

This is cosmetic (help output only); skip it for a rule in an existing
service.

## 8. Tests

Tests live in `tests/` (repo root, **not** inside the package). Fixtures live
in `tests/fixtures/`. Follow the existing pattern (see
[`tests/test_rules.py`](../../tests/test_rules.py) and
[`tests/test_azure_rules.py`](../../tests/test_azure_rules.py)):

1. Add a **vulnerable** fixture that should trigger exactly one finding and a
   **clean** fixture that should trigger none.
2. Assert the rule fires (and fires once) on the vulnerable input and stays
   silent on the clean input. Unit-test the rule class directly for edge cases
   (type coercion, exemptions like CORS `OPTIONS`).
3. Optionally add the category to a `RuleRegistry(enabled={...})` filter test.

```python
from cloudspill.rules.aws.api_gateway.apigw_007_example import APIGatewayExample
from cloudspill.models.nodes import IaCNode
from cloudspill.models.graph import ResourceGraph

def _node(rt, **attrs):
    return IaCNode(node_id="n", node_type="resource", resource_type=rt,
                   name="x", attributes=attrs, children=(),
                   source_file="f.tf", line=1)

def test_fires_on_violation():
    findings = APIGatewayExample().check(
        _node("aws_api_gateway_method", some_flag=True), ResourceGraph())
    assert len(findings) == 1

def test_clean_passes():
    findings = APIGatewayExample().check(
        _node("aws_api_gateway_method", some_flag=False), ResourceGraph())
    assert findings == []
```

Run:

```bash
pytest tests/ -q
```

## 9. Update the README

[`README.md`](../../README.md) advertises a rule count and a coverage list
(e.g. "36+ rules — AWS (S3, IAM, EC2, RDS, Docker) and Azure (...)"). Keep
these honest when you add rules or a new service.

## 10. Sanity-check end to end

```bash
# Discovery + filtering
python -c "from cloudspill.rules import RuleRegistry; \
print([r.rule_id for r in RuleRegistry(enabled={'apigw'}).rules])"

# Real scan against your fixture
cloudspill tests/fixtures/<your-fixture> --rules apigw
```

You should see your rule ID in the first command and exactly the expected
finding(s) in the second.

---

## What you touched, at a glance

| Change                         | Existing service | New service/cloud |
|--------------------------------|:----------------:|:-----------------:|
| Rule file under `rules/...`    | ✅               | ✅                |
| `@register` + correct `rule_id`| ✅               | ✅                |
| Service `__init__.py` table    | ✅               | ✅ (new file)     |
| Package `__init__.py` markers  | —                | ✅ (every dir)    |
| `_RULE_CHOICES` in `cli.py`    | —                | ✅                |
| Tests + fixtures               | ✅               | ✅                |
| `README.md` counts/coverage    | ✅               | ✅                |
| Parser changes                 | rarely           | rarely            |
