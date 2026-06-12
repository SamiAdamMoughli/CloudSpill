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


# ─── EC2 Rules ───────────────────────────────────────────────────────

from cloudspill.rules.ec2 import EC2SSHOpen, EC2OpenIngress, EC2NoIMDSv2, EC2PublicIP


class TestEC2SSHOpen:
    def test_ssh_open_triggers(self) -> None:
        node = _make_node("aws_security_group.web", "aws_security_group", {
            "ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]
        })
        findings = EC2SSHOpen().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "EC2-001"
        assert findings[0].severity == Severity.CRITICAL

    def test_ssh_private_clean(self) -> None:
        node = _make_node("aws_security_group.web", "aws_security_group", {
            "ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]}]
        })
        assert EC2SSHOpen().check(node, _empty_graph()) == []

    def test_ipv6_open_triggers(self) -> None:
        node = _make_node("aws_security_group.web", "aws_security_group", {
            "ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["::/0"]}]
        })
        assert len(EC2SSHOpen().check(node, _empty_graph())) == 1

    def test_wrong_resource_skipped(self) -> None:
        node = _make_node("aws_instance.test", "aws_instance", {
            "ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]
        })
        assert EC2SSHOpen().check(node, _empty_graph()) == []


class TestEC2OpenIngress:
    def test_open_8080_triggers(self) -> None:
        node = _make_node("aws_security_group.web", "aws_security_group", {
            "ingress": [{"from_port": 8080, "to_port": 8080, "cidr_blocks": ["0.0.0.0/0"]}]
        })
        findings = EC2OpenIngress().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "EC2-002"

    def test_ssh_not_duplicated(self) -> None:
        """EC2-002 skips port 22 to avoid overlap with EC2-001."""
        node = _make_node("aws_security_group.web", "aws_security_group", {
            "ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]
        })
        assert EC2OpenIngress().check(node, _empty_graph()) == []

    def test_private_cidr_clean(self) -> None:
        node = _make_node("aws_security_group.web", "aws_security_group", {
            "ingress": [{"from_port": 443, "to_port": 443, "cidr_blocks": ["10.0.0.0/8"]}]
        })
        assert EC2OpenIngress().check(node, _empty_graph()) == []


class TestEC2NoIMDSv2:
    def test_no_metadata_triggers(self) -> None:
        node = _make_node("aws_instance.web", "aws_instance", {"ami": "ami-123"})
        assert len(EC2NoIMDSv2().check(node, _empty_graph())) == 1

    def test_imdsv2_required_clean(self) -> None:
        node = _make_node("aws_instance.web", "aws_instance", {
            "metadata_options": {"http_tokens": "required"}
        })
        assert EC2NoIMDSv2().check(node, _empty_graph()) == []

    def test_imdsv1_optional_triggers(self) -> None:
        node = _make_node("aws_instance.web", "aws_instance", {
            "metadata_options": {"http_tokens": "optional"}
        })
        assert len(EC2NoIMDSv2().check(node, _empty_graph())) == 1


class TestEC2PublicIP:
    def test_public_ip_triggers(self) -> None:
        node = _make_node("aws_instance.web", "aws_instance", {
            "associate_public_ip_address": True
        })
        findings = EC2PublicIP().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "EC2-004"

    def test_no_public_ip_clean(self) -> None:
        node = _make_node("aws_instance.web", "aws_instance", {
            "associate_public_ip_address": False
        })
        assert EC2PublicIP().check(node, _empty_graph()) == []

    def test_missing_attribute_clean(self) -> None:
        node = _make_node("aws_instance.web", "aws_instance", {})
        assert EC2PublicIP().check(node, _empty_graph()) == []


# ─── RDS Rules ───────────────────────────────────────────────────────

from cloudspill.rules.rds import (
    RDSPubliclyAccessible, RDSNoEncryption, RDSNoDeletionProtection, RDSNoBackups,
)


class TestRDSPubliclyAccessible:
    def test_public_triggers(self) -> None:
        node = _make_node("aws_db_instance.db", "aws_db_instance", {
            "publicly_accessible": True
        })
        findings = RDSPubliclyAccessible().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "RDS-001"
        assert findings[0].severity == Severity.CRITICAL

    def test_private_clean(self) -> None:
        node = _make_node("aws_db_instance.db", "aws_db_instance", {
            "publicly_accessible": False
        })
        assert RDSPubliclyAccessible().check(node, _empty_graph()) == []

    def test_rds_cluster_also_caught(self) -> None:
        node = _make_node("aws_rds_cluster.db", "aws_rds_cluster", {
            "publicly_accessible": True
        })
        assert len(RDSPubliclyAccessible().check(node, _empty_graph())) == 1


class TestRDSNoEncryption:
    def test_no_encryption_triggers(self) -> None:
        node = _make_node("aws_db_instance.db", "aws_db_instance", {})
        assert len(RDSNoEncryption().check(node, _empty_graph())) == 1

    def test_encrypted_clean(self) -> None:
        node = _make_node("aws_db_instance.db", "aws_db_instance", {
            "storage_encrypted": True
        })
        assert RDSNoEncryption().check(node, _empty_graph()) == []


class TestRDSNoDeletionProtection:
    def test_no_protection_triggers(self) -> None:
        node = _make_node("aws_db_instance.db", "aws_db_instance", {})
        assert len(RDSNoDeletionProtection().check(node, _empty_graph())) == 1

    def test_protected_clean(self) -> None:
        node = _make_node("aws_db_instance.db", "aws_db_instance", {
            "deletion_protection": True
        })
        assert RDSNoDeletionProtection().check(node, _empty_graph()) == []


class TestRDSNoBackups:
    def test_zero_retention_triggers(self) -> None:
        node = _make_node("aws_db_instance.db", "aws_db_instance", {
            "backup_retention_period": 0
        })
        findings = RDSNoBackups().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "RDS-004"

    def test_positive_retention_clean(self) -> None:
        node = _make_node("aws_db_instance.db", "aws_db_instance", {
            "backup_retention_period": 7
        })
        assert RDSNoBackups().check(node, _empty_graph()) == []

    def test_missing_retention_clean(self) -> None:
        """AWS defaults to 1 day — no finding if not set."""
        node = _make_node("aws_db_instance.db", "aws_db_instance", {})
        assert RDSNoBackups().check(node, _empty_graph()) == []


# ─── Docker Rules ────────────────────────────────────────────────────

from cloudspill.parsers.docker import DockerfileParser as DParser
from cloudspill.rules.docker import (
    DockerRootUser, DockerNoUserInstruction, DockerLatestTag,
    DockerSecretInEnv, DockerAddInsteadOfCopy, DockerUnchainedRun,
)


class TestDockerRootUser:
    def test_explicit_root_triggers(self) -> None:
        node = _make_node("dockerfile.d.USER.0", "USER", {"user": "root"})
        assert len(DockerRootUser().check(node, _empty_graph())) == 1

    def test_nonroot_user_clean(self) -> None:
        node = _make_node("dockerfile.d.USER.0", "USER", {"user": "nobody"})
        assert DockerRootUser().check(node, _empty_graph()) == []


class TestDockerNoUserInstruction:
    def test_no_user_triggers(self) -> None:
        from_node = _make_node("dockerfile.d.FROM.0", "FROM", {"image": "python", "tag": "latest"})
        graph = ResourceGraph.build([from_node])
        findings = DockerNoUserInstruction().check(from_node, graph)
        assert len(findings) == 1

    def test_user_present_clean(self) -> None:
        from_node = _make_node("dockerfile.d.FROM.0", "FROM", {"image": "python", "tag": "3.12"})
        user_node = IaCNode(
            node_id="dockerfile.d.USER.0", node_type="instruction",
            resource_type="USER", name="USER nobody",
            attributes={"user": "nobody"}, children=(),
            source_file="test.tf", line=10,
        )
        graph = ResourceGraph.build([from_node, user_node])
        assert DockerNoUserInstruction().check(from_node, graph) == []


class TestDockerLatestTag:
    def test_latest_triggers(self) -> None:
        node = _make_node("dockerfile.d.FROM.0", "FROM", {"image": "python", "tag": "latest"})
        findings = DockerLatestTag().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "DOCKER-003"

    def test_pinned_clean(self) -> None:
        node = _make_node("dockerfile.d.FROM.0", "FROM", {"image": "python", "tag": "3.12-slim"})
        assert DockerLatestTag().check(node, _empty_graph()) == []


class TestDockerSecretInEnv:
    def test_aws_key_triggers(self) -> None:
        node = _make_node("dockerfile.d.ENV.0", "ENV", {
            "AWS_SECRET_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE"
        })
        assert len(DockerSecretInEnv().check(node, _empty_graph())) == 1

    def test_db_url_triggers(self) -> None:
        node = _make_node("dockerfile.d.ENV.0", "ENV", {
            "DATABASE_URL": "postgresql://admin:secret@db:5432/prod"
        })
        assert len(DockerSecretInEnv().check(node, _empty_graph())) == 1

    def test_safe_env_clean(self) -> None:
        node = _make_node("dockerfile.d.ENV.0", "ENV", {"APP_NAME": "cloudspill"})
        assert DockerSecretInEnv().check(node, _empty_graph()) == []


class TestDockerAddInsteadOfCopy:
    def test_local_add_triggers(self) -> None:
        node = _make_node("dockerfile.d.ADD.0", "ADD", {"src": "./app", "dst": "/opt/app"})
        assert len(DockerAddInsteadOfCopy().check(node, _empty_graph())) == 1

    def test_url_add_clean(self) -> None:
        node = _make_node("dockerfile.d.ADD.0", "ADD", {"src": "https://example.com/file.tar.gz", "dst": "/opt"})
        assert DockerAddInsteadOfCopy().check(node, _empty_graph()) == []

    def test_tar_add_clean(self) -> None:
        node = _make_node("dockerfile.d.ADD.0", "ADD", {"src": "archive.tar.gz", "dst": "/opt"})
        assert DockerAddInsteadOfCopy().check(node, _empty_graph()) == []


class TestDockerUnchainedRun:
    def test_three_runs_triggers(self) -> None:
        runs = [
            _make_node(f"dockerfile.d.RUN.{i}", "RUN", {"command": f"cmd{i}"})
            for i in range(3)
        ]
        graph = ResourceGraph.build(runs)
        # Only fires on the first RUN
        assert len(DockerUnchainedRun().check(runs[0], graph)) == 1
        assert DockerUnchainedRun().check(runs[1], graph) == []

    def test_two_runs_clean(self) -> None:
        runs = [
            _make_node(f"dockerfile.d.RUN.{i}", "RUN", {"command": f"cmd{i}"})
            for i in range(2)
        ]
        graph = ResourceGraph.build(runs)
        assert DockerUnchainedRun().check(runs[0], graph) == []


# ─── Docker Fixture Integration ─────────────────────────────────────


class TestDockerFixtureIntegration:
    @pytest.fixture()
    def findings(self) -> list[Finding]:
        nodes = DParser().parse(FIXTURES / "Dockerfile.vulnerable")
        graph = ResourceGraph.build(nodes)
        return RuleEngine(RuleRegistry(enabled={"docker"})).evaluate(nodes, graph)

    def test_docker_001_found(self, findings: list[Finding]) -> None:
        assert any(f.rule_id == "DOCKER-001" for f in findings)

    def test_docker_003_found(self, findings: list[Finding]) -> None:
        assert any(f.rule_id == "DOCKER-003" for f in findings)

    def test_docker_004_found(self, findings: list[Finding]) -> None:
        assert any(f.rule_id == "DOCKER-004" for f in findings)

    def test_docker_005_found(self, findings: list[Finding]) -> None:
        assert any(f.rule_id == "DOCKER-005" for f in findings)

    def test_docker_006_found(self, findings: list[Finding]) -> None:
        assert any(f.rule_id == "DOCKER-006" for f in findings)

    def test_secrets_detected_count(self, findings: list[Finding]) -> None:
        secrets = [f for f in findings if f.rule_id == "DOCKER-004"]
        assert len(secrets) == 2  # AWS key + DATABASE_URL
