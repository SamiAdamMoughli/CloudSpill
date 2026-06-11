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

## Quality Gates

All contributions must pass:

- `mypy --strict`
- `pylint` score ≥ 9.0
- `bandit` clean
- `pytest` passing
- `black` + `isort` formatted