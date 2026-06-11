"""Rule registry — collects all rule classes, supports filtering."""

from __future__ import annotations

from cloudspill.rules.base import Rule


class RuleRegistry:
    """Discovers and holds all available rules, with optional filtering."""

    def __init__(self, enabled: set[str] | None = None) -> None:
        self._enabled = enabled
        self._rules: list[Rule] = []
        self._discover()

    def _discover(self) -> None:
        """Import rule modules and collect Rule implementations."""
        raise NotImplementedError

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)
