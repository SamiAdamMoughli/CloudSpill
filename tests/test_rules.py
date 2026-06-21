"""Tests for the RuleEngine and RuleRegistry.

Per-service rule coverage lives in the dedicated test_*_rules.py modules under
cloudspill.rules.aws.*. (The legacy flat S3/IAM/EC2/RDS rule modules and the
Azure/Docker rule sets these tests once targeted have been removed pending a
modular rebuild.)
"""

from __future__ import annotations

from typing import Any

from cloudspill.engine.rule_engine import RuleEngine
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules import RuleRegistry


def _make_node(
    node_id: str,
    resource_type: str,
    attributes: dict[str, Any] | None = None,
    children: tuple[IaCNode, ...] = (),
) -> IaCNode:
    return IaCNode(
        node_id=node_id,
        node_type="resource",
        resource_type=resource_type,
        name=node_id.split(".")[-1],
        attributes=attributes or {},
        children=children,
        source_file="test.tf",
        line=1,
    )


class TestRuleEngine:
    def test_returns_findings(self) -> None:
        node = _make_node("aws_s3_bucket.test", "aws_s3_bucket", {"acl": "public-read"})
        graph = ResourceGraph.build([node])
        engine = RuleEngine(RuleRegistry(enabled={"s3"}))
        findings = engine.evaluate([node], graph)
        assert len(findings) > 0

    def test_deduplicates_findings(self) -> None:
        node = _make_node("aws_s3_bucket.test", "aws_s3_bucket", {"acl": "public-read"})
        graph = ResourceGraph.build([node])
        engine = RuleEngine(RuleRegistry(enabled={"s3"}))
        findings = engine.evaluate([node, node], graph)
        s3_001 = [f for f in findings if f.rule_id == "S3-001"]
        assert len(s3_001) == 1

    def test_empty_nodes(self) -> None:
        engine = RuleEngine(RuleRegistry())
        assert engine.evaluate([], ResourceGraph()) == []


class TestRuleRegistry:
    def test_all_rules_loaded(self) -> None:
        registry = RuleRegistry()
        assert len(registry.rules) >= 10

    def test_filter_s3_only(self) -> None:
        registry = RuleRegistry(enabled={"s3"})
        for rule in registry.rules:
            assert rule.rule_id.startswith("S3")

    def test_filter_iam_only(self) -> None:
        registry = RuleRegistry(enabled={"iam"})
        for rule in registry.rules:
            assert rule.rule_id.startswith("IAM")

    def test_filter_nonexistent_returns_empty(self) -> None:
        registry = RuleRegistry(enabled={"nonexistent"})
        assert len(registry.rules) == 0
