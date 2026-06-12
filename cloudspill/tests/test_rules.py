"""Tests for S3 and IAM security rules + RuleEngine."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from cloudspill.engine.rule_engine import RuleEngine
from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.parsers.terraform import TerraformParser
from cloudspill.rules import RuleRegistry
from cloudspill.rules.s3 import (
    S3BlockPublicAccess,
    S3NoEncryption,
    S3NoLogging,
    S3NoVersioning,
    S3PublicACL,
)
from cloudspill.rules.iam import (
    IAMAdminAccess,
    IAMInlinePolicy,
    IAMNoMFA,
    IAMWildcardAction,
    IAMWildcardResource,
)

FIXTURES = Path(__file__).parent / "fixtures"


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


def _empty_graph() -> ResourceGraph:
    return ResourceGraph()


# ─── RuleEngine ──────────────────────────────────────────────────────


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


# ─── S3 Rules ────────────────────────────────────────────────────────


class TestS3PublicACL:
    def test_public_read_triggers(self) -> None:
        node = _make_node("aws_s3_bucket.test", "aws_s3_bucket", {"acl": "public-read"})
        findings = S3PublicACL().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "S3-001"
        assert findings[0].severity == Severity.CRITICAL

    def test_public_read_write_triggers(self) -> None:
        node = _make_node("aws_s3_bucket.test", "aws_s3_bucket", {"acl": "public-read-write"})
        assert len(S3PublicACL().check(node, _empty_graph())) == 1

    def test_private_acl_clean(self) -> None:
        node = _make_node("aws_s3_bucket.test", "aws_s3_bucket", {"acl": "private"})
        assert S3PublicACL().check(node, _empty_graph()) == []

    def test_no_acl_clean(self) -> None:
        node = _make_node("aws_s3_bucket.test", "aws_s3_bucket", {})
        assert S3PublicACL().check(node, _empty_graph()) == []

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node("aws_instance.test", "aws_instance", {"acl": "public-read"})
        assert S3PublicACL().check(node, _empty_graph()) == []


class TestS3BlockPublicAccess:
    def test_all_false_triggers(self) -> None:
        node = _make_node("aws_s3_bucket_public_access_block.test", "aws_s3_bucket_public_access_block", {
            "block_public_acls": False,
            "block_public_policy": False,
            "ignore_public_acls": False,
            "restrict_public_buckets": False,
        })
        findings = S3BlockPublicAccess().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "S3-002"

    def test_one_false_triggers(self) -> None:
        node = _make_node("aws_s3_bucket_public_access_block.test", "aws_s3_bucket_public_access_block", {
            "block_public_acls": True,
            "block_public_policy": False,
        })
        assert len(S3BlockPublicAccess().check(node, _empty_graph())) == 1

    def test_all_true_clean(self) -> None:
        node = _make_node("aws_s3_bucket_public_access_block.test", "aws_s3_bucket_public_access_block", {
            "block_public_acls": True,
            "block_public_policy": True,
            "ignore_public_acls": True,
            "restrict_public_buckets": True,
        })
        assert S3BlockPublicAccess().check(node, _empty_graph()) == []


class TestS3NoEncryption:
    def test_no_encryption_triggers(self) -> None:
        node = _make_node("aws_s3_bucket.test", "aws_s3_bucket", {"bucket": "test"})
        graph = ResourceGraph.build([node])
        findings = S3NoEncryption().check(node, graph)
        assert len(findings) == 1
        assert findings[0].rule_id == "S3-003"

    def test_encryption_in_attributes_clean(self) -> None:
        node = _make_node("aws_s3_bucket.test", "aws_s3_bucket", {
            "server_side_encryption_configuration": {"rule": {}}
        })
        assert S3NoEncryption().check(node, ResourceGraph.build([node])) == []


class TestS3NoLogging:
    def test_no_logging_triggers(self) -> None:
        node = _make_node("aws_s3_bucket.test", "aws_s3_bucket", {"bucket": "test"})
        findings = S3NoLogging().check(node, ResourceGraph.build([node]))
        assert len(findings) == 1
        assert findings[0].rule_id == "S3-004"

    def test_logging_present_clean(self) -> None:
        node = _make_node("aws_s3_bucket.test", "aws_s3_bucket", {
            "logging": {"target_bucket": "logs"}
        })
        assert S3NoLogging().check(node, ResourceGraph.build([node])) == []


class TestS3NoVersioning:
    def test_no_versioning_triggers(self) -> None:
        node = _make_node("aws_s3_bucket.test", "aws_s3_bucket", {"bucket": "test"})
        findings = S3NoVersioning().check(node, ResourceGraph.build([node]))
        assert len(findings) == 1
        assert findings[0].rule_id == "S3-005"

    def test_versioning_present_clean(self) -> None:
        node = _make_node("aws_s3_bucket.test", "aws_s3_bucket", {
            "versioning": {"enabled": True}
        })
        assert S3NoVersioning().check(node, ResourceGraph.build([node])) == []


# ─── S3 Fixture Integration ─────────────────────────────────────────


class TestS3FixtureIntegration:
    @pytest.fixture()
    def findings(self) -> list[Finding]:
        nodes = TerraformParser().parse(FIXTURES / "s3_public.tf")
        graph = ResourceGraph.build(nodes)
        return RuleEngine(RuleRegistry(enabled={"s3"})).evaluate(nodes, graph)

    def test_s3_001_found(self, findings: list[Finding]) -> None:
        assert any(f.rule_id == "S3-001" for f in findings)

    def test_s3_002_found(self, findings: list[Finding]) -> None:
        assert any(f.rule_id == "S3-002" for f in findings)

    def test_s3_003_found(self, findings: list[Finding]) -> None:
        assert any(f.rule_id == "S3-003" for f in findings)

    def test_s3_004_found(self, findings: list[Finding]) -> None:
        assert any(f.rule_id == "S3-004" for f in findings)

    def test_s3_005_found(self, findings: list[Finding]) -> None:
        assert any(f.rule_id == "S3-005" for f in findings)

    def test_finding_has_correct_resource(self, findings: list[Finding]) -> None:
        s3_001 = next(f for f in findings if f.rule_id == "S3-001")
        assert s3_001.resource == "aws_s3_bucket.vulnerable_bucket"

    def test_finding_has_file(self, findings: list[Finding]) -> None:
        for f in findings:
            assert f.file.endswith("s3_public.tf")

    def test_finding_has_line(self, findings: list[Finding]) -> None:
        for f in findings:
            assert f.line > 0


# ─── IAM Rules ───────────────────────────────────────────────────────


class TestIAMWildcardAction:
    def test_wildcard_triggers(self) -> None:
        policy = '{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
        node = _make_node("aws_iam_policy.test", "aws_iam_policy", {"policy": policy})
        findings = IAMWildcardAction().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "IAM-001"
        assert findings[0].severity == Severity.CRITICAL

    def test_specific_action_clean(self) -> None:
        policy = '{"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}'
        node = _make_node("aws_iam_policy.test", "aws_iam_policy", {"policy": policy})
        assert IAMWildcardAction().check(node, _empty_graph()) == []

    def test_deny_effect_skipped(self) -> None:
        policy = '{"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}'
        node = _make_node("aws_iam_policy.test", "aws_iam_policy", {"policy": policy})
        assert IAMWildcardAction().check(node, _empty_graph()) == []

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node("aws_s3_bucket.test", "aws_s3_bucket", {"policy": "{}"})
        assert IAMWildcardAction().check(node, _empty_graph()) == []


class TestIAMWildcardResource:
    def test_write_with_wildcard_triggers(self) -> None:
        policy = '{"Statement": [{"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "*"}]}'
        node = _make_node("aws_iam_policy.test", "aws_iam_policy", {"policy": policy})
        findings = IAMWildcardResource().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "IAM-002"

    def test_read_only_clean(self) -> None:
        policy = '{"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]}'
        node = _make_node("aws_iam_policy.test", "aws_iam_policy", {"policy": policy})
        assert IAMWildcardResource().check(node, _empty_graph()) == []

    def test_specific_resource_clean(self) -> None:
        policy = '{"Statement": [{"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "arn:aws:s3:::bucket/*"}]}'
        node = _make_node("aws_iam_policy.test", "aws_iam_policy", {"policy": policy})
        assert IAMWildcardResource().check(node, _empty_graph()) == []


class TestIAMAdminAccess:
    def test_admin_policy_triggers(self) -> None:
        node = _make_node("aws_iam_role_policy_attachment.test", "aws_iam_role_policy_attachment", {
            "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"
        })
        findings = IAMAdminAccess().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "IAM-003"

    def test_power_user_triggers(self) -> None:
        node = _make_node("aws_iam_role_policy_attachment.test", "aws_iam_role_policy_attachment", {
            "policy_arn": "arn:aws:iam::aws:policy/PowerUserAccess"
        })
        assert len(IAMAdminAccess().check(node, _empty_graph())) == 1

    def test_readonly_clean(self) -> None:
        node = _make_node("aws_iam_role_policy_attachment.test", "aws_iam_role_policy_attachment", {
            "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"
        })
        assert IAMAdminAccess().check(node, _empty_graph()) == []


class TestIAMNoMFA:
    def test_no_mfa_triggers(self) -> None:
        policy = '{"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}'
        node = _make_node("aws_iam_policy.test", "aws_iam_policy", {"policy": policy})
        findings = IAMNoMFA().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "IAM-004"

    def test_mfa_condition_clean(self) -> None:
        policy = '{"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]}'
        node = _make_node("aws_iam_policy.test", "aws_iam_policy", {"policy": policy})
        assert IAMNoMFA().check(node, _empty_graph()) == []


class TestIAMInlinePolicy:
    def test_inline_role_policy_triggers(self) -> None:
        node = _make_node("aws_iam_role_policy.test", "aws_iam_role_policy", {"policy": "{}"})
        findings = IAMInlinePolicy().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "IAM-005"

    def test_managed_policy_clean(self) -> None:
        node = _make_node("aws_iam_policy.test", "aws_iam_policy", {"policy": "{}"})
        assert IAMInlinePolicy().check(node, _empty_graph()) == []


# ─── IAM Fixture Integration ────────────────────────────────────────


class TestIAMFixtureIntegration:
    @pytest.fixture()
    def findings(self) -> list[Finding]:
        nodes = TerraformParser().parse(FIXTURES / "iam_wildcard.tf")
        graph = ResourceGraph.build(nodes)
        return RuleEngine(RuleRegistry(enabled={"iam"})).evaluate(nodes, graph)

    def test_iam_001_found(self, findings: list[Finding]) -> None:
        assert any(f.rule_id == "IAM-001" for f in findings)

    def test_iam_002_found(self, findings: list[Finding]) -> None:
        assert any(f.rule_id == "IAM-002" for f in findings)

    def test_iam_003_found(self, findings: list[Finding]) -> None:
        assert any(f.rule_id == "IAM-003" for f in findings)

    def test_iam_004_found(self, findings: list[Finding]) -> None:
        assert any(f.rule_id == "IAM-004" for f in findings)

    def test_iam_005_found(self, findings: list[Finding]) -> None:
        assert any(f.rule_id == "IAM-005" for f in findings)
