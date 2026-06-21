# Summary

<!-- What does this change and why? Link any issue it closes, e.g. "Closes #12". -->

## Type of change

- [ ] New rule(s)
- [ ] Bug fix (incl. false positive / false negative)
- [ ] New parser / output format / provider
- [ ] Refactor / internal change
- [ ] Docs only

## For a new or changed rule

<!-- Delete this section if not applicable. -->

- **Rule ID(s):**
- **Resource type(s):**
- **Severity:**
- **What it flags / why it's safe to skip otherwise:**

## Checklist

- [ ] Added/updated tests, including a **vulnerable** fixture (fires once) and a **clean** fixture (stays silent)
- [ ] Updated the service `__init__.py` rule table and any affected docs (README count, developer guide)
- [ ] `pytest` passes
- [ ] `black --check`, `isort --check`, `mypy --strict`, and `pylint` pass
- [ ] `bandit -r cloudspill/ -c pyproject.toml` is clean

<!-- The CI workflow runs all of the above on every PR. -->
