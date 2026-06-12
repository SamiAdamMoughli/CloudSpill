"""Rule registry — collects all rule classes, supports filtering."""

from __future__ import annotations

from typing import Any


class RuleRegistry:
    """Discovers and holds all available rules, with optional filtering."""

    def __init__(self, enabled: set[str] | None = None) -> None:
        self._enabled = enabled
        self._rules: list[Any] = []
        self._discover()

    def _discover(self) -> None:
        """Import rule modules and collect Rule implementations."""
        from cloudspill.rules.docker import DOCKER_RULES
        from cloudspill.rules.ec2 import EC2_RULES
        from cloudspill.rules.iam import IAM_RULES
        from cloudspill.rules.rds import RDS_RULES
        from cloudspill.rules.s3 import S3_RULES

        all_rules: list[Any] = [
            *S3_RULES,
            *IAM_RULES,
            *EC2_RULES,
            *RDS_RULES,
            *DOCKER_RULES,
        ]

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
    def rules(self) -> list[Any]:
        return list(self._rules)
