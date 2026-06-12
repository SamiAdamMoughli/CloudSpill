"""Rule registry — auto-discovers all rule classes via @register, supports filtering."""

from __future__ import annotations

import importlib
import pkgutil

from cloudspill.rules.base import Rule


class RuleRegistry:  # pylint: disable=too-few-public-methods
    """Discovers and holds all available rules, with optional filtering.

    Rule discovery is automatic: any module inside cloudspill.rules that
    decorates its rule classes with @register will be picked up without
    any changes here. Adding a new rule file is zero-config.
    """

    def __init__(self, enabled: set[str] | None = None) -> None:
        self._enabled = enabled
        self._rules: list[Rule] = []
        self._discover()

    def _discover(self) -> None:
        """Import every rule module to trigger @register, then collect results."""
        import cloudspill.rules as pkg  # local to avoid circular at module level

        for _, name, _ in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
            if not name.endswith(".base"):
                importlib.import_module(name)

        from cloudspill.rules.base import get_registered_rules

        all_rules = get_registered_rules()

        if self._enabled is not None:
            self._rules = [
                r for r in all_rules if self._rule_category(r.rule_id) in self._enabled
            ]
        else:
            self._rules = all_rules

    @staticmethod
    def _rule_category(rule_id: str) -> str:
        """Extract category from rule ID: 'S3-001' → 's3'."""
        return rule_id.split("-")[0].lower()

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)
