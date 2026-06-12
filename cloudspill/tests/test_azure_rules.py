"""Tests for Azure security rules + fixture integration."""

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
from cloudspill.rules.azure import (
    AZFunctionAppHttps,
    AZNSGOpenIngress,
    AZNSGSSHOpen,
    AZPostgresFirewallOpen,
    AZPostgresNoSSL,
    AZPostgresPublicAccess,
    AZRBACOverPrivileged,
    AZStorageBlobPublic,
    AZStorageContainerPublic,
    AZStorageHttps,
    AZStorageWeakTLS,
    AZVMPasswordAuth,
    AZVMPublicIP,
)

AZURE_FIXTURES = (
    Path(__file__).parent / "fixtures" / "examples" / "vulneable-azure-stack"
)


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


# ─── AZ-STG-001: Storage HTTPS ───────────────────────────────────────


class TestAZStorageHttps:
    def test_https_disabled_triggers(self) -> None:
        node = _make_node(
            "azurerm_storage_account.sa",
            "azurerm_storage_account",
            {"enable_https_traffic_only": False},
        )
        findings = AZStorageHttps().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "AZ-STG-001"
        assert findings[0].severity == Severity.HIGH

    def test_https_enabled_clean(self) -> None:
        node = _make_node(
            "azurerm_storage_account.sa",
            "azurerm_storage_account",
            {"enable_https_traffic_only": True},
        )
        assert AZStorageHttps().check(node, _empty_graph()) == []

    def test_attribute_missing_clean(self) -> None:
        node = _make_node("azurerm_storage_account.sa", "azurerm_storage_account", {})
        assert AZStorageHttps().check(node, _empty_graph()) == []

    def test_wrong_resource_type_skipped(self) -> None:
        node = _make_node(
            "azurerm_storage_container.c",
            "azurerm_storage_container",
            {"enable_https_traffic_only": False},
        )
        assert AZStorageHttps().check(node, _empty_graph()) == []


# ─── AZ-STG-002: Storage blob public ─────────────────────────────────


class TestAZStorageBlobPublic:
    def test_public_blob_triggers(self) -> None:
        node = _make_node(
            "azurerm_storage_account.sa",
            "azurerm_storage_account",
            {"allow_nested_items_to_be_public": True},
        )
        findings = AZStorageBlobPublic().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "AZ-STG-002"
        assert findings[0].severity == Severity.HIGH

    def test_public_blob_false_clean(self) -> None:
        node = _make_node(
            "azurerm_storage_account.sa",
            "azurerm_storage_account",
            {"allow_nested_items_to_be_public": False},
        )
        assert AZStorageBlobPublic().check(node, _empty_graph()) == []

    def test_attribute_missing_clean(self) -> None:
        node = _make_node("azurerm_storage_account.sa", "azurerm_storage_account", {})
        assert AZStorageBlobPublic().check(node, _empty_graph()) == []


# ─── AZ-STG-003: Storage weak TLS ────────────────────────────────────


class TestAZStorageWeakTLS:
    def test_tls10_triggers(self) -> None:
        node = _make_node(
            "azurerm_storage_account.sa",
            "azurerm_storage_account",
            {"min_tls_version": "TLS1_0"},
        )
        findings = AZStorageWeakTLS().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "AZ-STG-003"
        assert findings[0].severity == Severity.MEDIUM

    def test_tls11_triggers(self) -> None:
        node = _make_node(
            "azurerm_storage_account.sa",
            "azurerm_storage_account",
            {"min_tls_version": "TLS1_1"},
        )
        assert len(AZStorageWeakTLS().check(node, _empty_graph())) == 1

    def test_tls12_clean(self) -> None:
        node = _make_node(
            "azurerm_storage_account.sa",
            "azurerm_storage_account",
            {"min_tls_version": "TLS1_2"},
        )
        assert AZStorageWeakTLS().check(node, _empty_graph()) == []

    def test_missing_defaults_to_tls12_clean(self) -> None:
        node = _make_node("azurerm_storage_account.sa", "azurerm_storage_account", {})
        assert AZStorageWeakTLS().check(node, _empty_graph()) == []


# ─── AZ-STG-004: Storage container public access ─────────────────────


class TestAZStorageContainerPublic:
    def test_container_access_triggers(self) -> None:
        node = _make_node(
            "azurerm_storage_container.c",
            "azurerm_storage_container",
            {"container_access_type": "container"},
        )
        findings = AZStorageContainerPublic().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "AZ-STG-004"
        assert findings[0].severity == Severity.CRITICAL

    def test_blob_access_triggers(self) -> None:
        node = _make_node(
            "azurerm_storage_container.c",
            "azurerm_storage_container",
            {"container_access_type": "blob"},
        )
        assert len(AZStorageContainerPublic().check(node, _empty_graph())) == 1

    def test_private_clean(self) -> None:
        node = _make_node(
            "azurerm_storage_container.c",
            "azurerm_storage_container",
            {"container_access_type": "private"},
        )
        assert AZStorageContainerPublic().check(node, _empty_graph()) == []

    def test_missing_defaults_private_clean(self) -> None:
        node = _make_node(
            "azurerm_storage_container.c", "azurerm_storage_container", {}
        )
        assert AZStorageContainerPublic().check(node, _empty_graph()) == []


# ─── AZ-NSG-001: SSH open ────────────────────────────────────────────


class TestAZNSGSSHOpen:
    def _nsg(self, **rule_overrides: Any) -> IaCNode:
        rule = {
            "direction": "Inbound",
            "access": "Allow",
            "source_address_prefix": "*",
            "destination_port_range": "22",
            **rule_overrides,
        }
        return _make_node(
            "azurerm_network_security_group.nsg",
            "azurerm_network_security_group",
            {"security_rule": [rule]},
        )

    def test_ssh_open_to_star_triggers(self) -> None:
        findings = AZNSGSSHOpen().check(self._nsg(), _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "AZ-NSG-001"
        assert findings[0].severity == Severity.CRITICAL

    def test_ssh_restricted_clean(self) -> None:
        node = self._nsg(source_address_prefix="10.0.0.0/8")
        assert AZNSGSSHOpen().check(node, _empty_graph()) == []

    def test_internet_prefix_triggers(self) -> None:
        node = self._nsg(source_address_prefix="Internet")
        assert len(AZNSGSSHOpen().check(node, _empty_graph())) == 1

    def test_outbound_skipped(self) -> None:
        node = self._nsg(direction="Outbound")
        assert AZNSGSSHOpen().check(node, _empty_graph()) == []

    def test_deny_rule_skipped(self) -> None:
        node = self._nsg(access="Deny")
        assert AZNSGSSHOpen().check(node, _empty_graph()) == []

    def test_no_security_rules_clean(self) -> None:
        node = _make_node(
            "azurerm_network_security_group.nsg", "azurerm_network_security_group", {}
        )
        assert AZNSGSSHOpen().check(node, _empty_graph()) == []

    def test_wrong_resource_skipped(self) -> None:
        node = _make_node("azurerm_virtual_network.vnet", "azurerm_virtual_network", {})
        assert AZNSGSSHOpen().check(node, _empty_graph()) == []


# ─── AZ-NSG-002: Open ingress ────────────────────────────────────────


class TestAZNSGOpenIngress:
    def _nsg(self, port: str = "8080", source: str = "*") -> IaCNode:
        rule = {
            "direction": "Inbound",
            "access": "Allow",
            "source_address_prefix": source,
            "destination_port_range": port,
        }
        return _make_node(
            "azurerm_network_security_group.nsg",
            "azurerm_network_security_group",
            {"security_rule": [rule]},
        )

    def test_open_port_8080_triggers(self) -> None:
        findings = AZNSGOpenIngress().check(self._nsg("8080"), _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "AZ-NSG-002"
        assert findings[0].severity == Severity.HIGH

    def test_ssh_port_not_duplicated(self) -> None:
        """AZ-NSG-002 skips port 22 to avoid overlap with AZ-NSG-001."""
        assert AZNSGOpenIngress().check(self._nsg("22"), _empty_graph()) == []

    def test_restricted_source_clean(self) -> None:
        assert (
            AZNSGOpenIngress().check(self._nsg(source="192.168.1.0/24"), _empty_graph())
            == []
        )

    def test_no_rules_clean(self) -> None:
        node = _make_node(
            "azurerm_network_security_group.nsg", "azurerm_network_security_group", {}
        )
        assert AZNSGOpenIngress().check(node, _empty_graph()) == []


# ─── AZ-VM-001: Password authentication ──────────────────────────────


class TestAZVMPasswordAuth:
    def test_password_enabled_triggers(self) -> None:
        node = _make_node(
            "azurerm_linux_virtual_machine.vm",
            "azurerm_linux_virtual_machine",
            {"disable_password_authentication": False},
        )
        findings = AZVMPasswordAuth().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "AZ-VM-001"
        assert findings[0].severity == Severity.HIGH

    def test_password_disabled_clean(self) -> None:
        node = _make_node(
            "azurerm_linux_virtual_machine.vm",
            "azurerm_linux_virtual_machine",
            {"disable_password_authentication": True},
        )
        assert AZVMPasswordAuth().check(node, _empty_graph()) == []

    def test_missing_attribute_clean(self) -> None:
        node = _make_node(
            "azurerm_linux_virtual_machine.vm", "azurerm_linux_virtual_machine", {}
        )
        assert AZVMPasswordAuth().check(node, _empty_graph()) == []

    def test_wrong_resource_skipped(self) -> None:
        node = _make_node(
            "azurerm_windows_virtual_machine.vm",
            "azurerm_windows_virtual_machine",
            {"disable_password_authentication": False},
        )
        assert AZVMPasswordAuth().check(node, _empty_graph()) == []


# ─── AZ-VM-002: Public IP via graph ──────────────────────────────────


class TestAZVMPublicIP:
    def test_vm_with_public_ip_triggers(self) -> None:
        vm = _make_node(
            "azurerm_linux_virtual_machine.vm",
            "azurerm_linux_virtual_machine",
            {"public_ip_address_id": "${azurerm_public_ip.pip.id}"},
        )
        pip = _make_node(
            "azurerm_public_ip.pip",
            "azurerm_public_ip",
            {"allocation_method": "Static"},
        )
        graph = ResourceGraph.build([vm, pip])
        findings = AZVMPublicIP().check(vm, graph)
        assert len(findings) == 1
        assert findings[0].rule_id == "AZ-VM-002"
        assert findings[0].severity == Severity.MEDIUM

    def test_vm_no_public_ip_clean(self) -> None:
        vm = _make_node(
            "azurerm_linux_virtual_machine.vm",
            "azurerm_linux_virtual_machine",
            {},
        )
        graph = ResourceGraph.build([vm])
        assert AZVMPublicIP().check(vm, graph) == []

    def test_wrong_resource_skipped(self) -> None:
        pip = _make_node("azurerm_public_ip.pip", "azurerm_public_ip", {})
        graph = ResourceGraph.build([pip])
        assert AZVMPublicIP().check(pip, graph) == []


# ─── AZ-DB-001: PostgreSQL public access ─────────────────────────────


class TestAZPostgresPublicAccess:
    def test_public_enabled_triggers(self) -> None:
        node = _make_node(
            "azurerm_postgresql_server.db",
            "azurerm_postgresql_server",
            {"public_network_access_enabled": True},
        )
        findings = AZPostgresPublicAccess().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "AZ-DB-001"
        assert findings[0].severity == Severity.CRITICAL

    def test_public_disabled_clean(self) -> None:
        node = _make_node(
            "azurerm_postgresql_server.db",
            "azurerm_postgresql_server",
            {"public_network_access_enabled": False},
        )
        assert AZPostgresPublicAccess().check(node, _empty_graph()) == []

    def test_missing_attribute_clean(self) -> None:
        node = _make_node(
            "azurerm_postgresql_server.db", "azurerm_postgresql_server", {}
        )
        assert AZPostgresPublicAccess().check(node, _empty_graph()) == []


# ─── AZ-DB-002: PostgreSQL no SSL ────────────────────────────────────


class TestAZPostgresNoSSL:
    def test_ssl_disabled_triggers(self) -> None:
        node = _make_node(
            "azurerm_postgresql_server.db",
            "azurerm_postgresql_server",
            {"ssl_enforcement_enabled": False},
        )
        findings = AZPostgresNoSSL().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "AZ-DB-002"
        assert findings[0].severity == Severity.HIGH

    def test_ssl_enabled_clean(self) -> None:
        node = _make_node(
            "azurerm_postgresql_server.db",
            "azurerm_postgresql_server",
            {"ssl_enforcement_enabled": True},
        )
        assert AZPostgresNoSSL().check(node, _empty_graph()) == []

    def test_missing_attribute_clean(self) -> None:
        node = _make_node(
            "azurerm_postgresql_server.db", "azurerm_postgresql_server", {}
        )
        assert AZPostgresNoSSL().check(node, _empty_graph()) == []


# ─── AZ-DB-003: PostgreSQL firewall open ─────────────────────────────


class TestAZPostgresFirewallOpen:
    def test_zero_start_ip_triggers(self) -> None:
        node = _make_node(
            "azurerm_postgresql_firewall_rule.fw",
            "azurerm_postgresql_firewall_rule",
            {"start_ip_address": "0.0.0.0", "end_ip_address": "255.255.255.255"},
        )
        findings = AZPostgresFirewallOpen().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "AZ-DB-003"
        assert findings[0].severity == Severity.CRITICAL

    def test_specific_ip_clean(self) -> None:
        node = _make_node(
            "azurerm_postgresql_firewall_rule.fw",
            "azurerm_postgresql_firewall_rule",
            {"start_ip_address": "10.0.0.5", "end_ip_address": "10.0.0.10"},
        )
        assert AZPostgresFirewallOpen().check(node, _empty_graph()) == []

    def test_missing_start_ip_clean(self) -> None:
        node = _make_node(
            "azurerm_postgresql_firewall_rule.fw",
            "azurerm_postgresql_firewall_rule",
            {},
        )
        assert AZPostgresFirewallOpen().check(node, _empty_graph()) == []

    def test_wrong_resource_skipped(self) -> None:
        node = _make_node(
            "azurerm_postgresql_server.db",
            "azurerm_postgresql_server",
            {"start_ip_address": "0.0.0.0"},
        )
        assert AZPostgresFirewallOpen().check(node, _empty_graph()) == []


# ─── AZ-RBAC-001: Over-privileged role assignment ────────────────────


class TestAZRBACOverPrivileged:
    def test_owner_triggers(self) -> None:
        node = _make_node(
            "azurerm_role_assignment.ra",
            "azurerm_role_assignment",
            {
                "role_definition_name": "Owner",
                "scope": "/subscriptions/00000000-0000-0000-0000-000000000000",
            },
        )
        findings = AZRBACOverPrivileged().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "AZ-RBAC-001"
        assert findings[0].severity == Severity.CRITICAL

    def test_contributor_triggers(self) -> None:
        node = _make_node(
            "azurerm_role_assignment.ra",
            "azurerm_role_assignment",
            {"role_definition_name": "Contributor", "scope": "/subscriptions/sub1"},
        )
        assert len(AZRBACOverPrivileged().check(node, _empty_graph())) == 1

    def test_reader_clean(self) -> None:
        node = _make_node(
            "azurerm_role_assignment.ra",
            "azurerm_role_assignment",
            {"role_definition_name": "Reader", "scope": "/subscriptions/sub1"},
        )
        assert AZRBACOverPrivileged().check(node, _empty_graph()) == []

    def test_storage_blob_reader_clean(self) -> None:
        node = _make_node(
            "azurerm_role_assignment.ra",
            "azurerm_role_assignment",
            {"role_definition_name": "Storage Blob Data Reader"},
        )
        assert AZRBACOverPrivileged().check(node, _empty_graph()) == []

    def test_wrong_resource_skipped(self) -> None:
        node = _make_node(
            "azurerm_role_definition.rd",
            "azurerm_role_definition",
            {"role_definition_name": "Owner"},
        )
        assert AZRBACOverPrivileged().check(node, _empty_graph()) == []


# ─── AZ-FUNC-001: Function App HTTPS ─────────────────────────────────


class TestAZFunctionAppHttps:
    def test_https_false_triggers(self) -> None:
        node = _make_node(
            "azurerm_linux_function_app.fn",
            "azurerm_linux_function_app",
            {"https_only": False},
        )
        findings = AZFunctionAppHttps().check(node, _empty_graph())
        assert len(findings) == 1
        assert findings[0].rule_id == "AZ-FUNC-001"
        assert findings[0].severity == Severity.HIGH

    def test_https_true_clean(self) -> None:
        node = _make_node(
            "azurerm_linux_function_app.fn",
            "azurerm_linux_function_app",
            {"https_only": True},
        )
        assert AZFunctionAppHttps().check(node, _empty_graph()) == []

    def test_missing_attribute_clean(self) -> None:
        node = _make_node(
            "azurerm_linux_function_app.fn", "azurerm_linux_function_app", {}
        )
        assert AZFunctionAppHttps().check(node, _empty_graph()) == []

    def test_wrong_resource_skipped(self) -> None:
        node = _make_node(
            "azurerm_windows_function_app.fn",
            "azurerm_windows_function_app",
            {"https_only": False},
        )
        assert AZFunctionAppHttps().check(node, _empty_graph()) == []


# ─── RuleRegistry: Azure category filter ─────────────────────────────


class TestAzureRuleRegistry:
    def test_az_rules_discovered(self) -> None:
        registry = RuleRegistry(enabled={"az"})
        ids = {r.rule_id for r in registry.rules}
        assert "AZ-STG-001" in ids
        assert "AZ-NSG-001" in ids
        assert "AZ-DB-001" in ids
        assert "AZ-RBAC-001" in ids
        assert "AZ-FUNC-001" in ids

    def test_az_filter_excludes_aws(self) -> None:
        registry = RuleRegistry(enabled={"az"})
        for rule in registry.rules:
            assert rule.rule_id.startswith("AZ-")

    def test_all_rules_includes_azure(self) -> None:
        registry = RuleRegistry()
        ids = {r.rule_id for r in registry.rules}
        assert "AZ-STG-001" in ids

    def test_thirteen_azure_rules_registered(self) -> None:
        registry = RuleRegistry(enabled={"az"})
        assert len(registry.rules) == 13


# ─── Fixture Integration ──────────────────────────────────────────────


@pytest.fixture()
def azure_findings() -> list[Finding]:
    nodes: list[IaCNode] = []
    parser = TerraformParser()
    for tf_file in sorted(AZURE_FIXTURES.glob("*.tf")):
        nodes.extend(parser.parse(tf_file))
    graph = ResourceGraph.build(nodes)
    return RuleEngine(RuleRegistry(enabled={"az"})).evaluate(nodes, graph)


class TestAzureFixtureIntegration:
    def test_stg_001_found(self, azure_findings: list[Finding]) -> None:
        assert any(f.rule_id == "AZ-STG-001" for f in azure_findings)

    def test_stg_002_found(self, azure_findings: list[Finding]) -> None:
        assert any(f.rule_id == "AZ-STG-002" for f in azure_findings)

    def test_stg_003_found(self, azure_findings: list[Finding]) -> None:
        assert any(f.rule_id == "AZ-STG-003" for f in azure_findings)

    def test_stg_004_found(self, azure_findings: list[Finding]) -> None:
        assert any(f.rule_id == "AZ-STG-004" for f in azure_findings)

    def test_nsg_001_found(self, azure_findings: list[Finding]) -> None:
        assert any(f.rule_id == "AZ-NSG-001" for f in azure_findings)

    def test_vm_001_found(self, azure_findings: list[Finding]) -> None:
        assert any(f.rule_id == "AZ-VM-001" for f in azure_findings)

    def test_db_001_found(self, azure_findings: list[Finding]) -> None:
        assert any(f.rule_id == "AZ-DB-001" for f in azure_findings)

    def test_db_002_found(self, azure_findings: list[Finding]) -> None:
        assert any(f.rule_id == "AZ-DB-002" for f in azure_findings)

    def test_db_003_found(self, azure_findings: list[Finding]) -> None:
        assert any(f.rule_id == "AZ-DB-003" for f in azure_findings)

    def test_rbac_001_found(self, azure_findings: list[Finding]) -> None:
        assert any(f.rule_id == "AZ-RBAC-001" for f in azure_findings)

    def test_func_001_found(self, azure_findings: list[Finding]) -> None:
        assert any(f.rule_id == "AZ-FUNC-001" for f in azure_findings)

    def test_storage_resource_id_correct(self, azure_findings: list[Finding]) -> None:
        stg = next(f for f in azure_findings if f.rule_id == "AZ-STG-001")
        assert stg.resource == "azurerm_storage_account.vuln_storage"

    def test_db_resource_id_correct(self, azure_findings: list[Finding]) -> None:
        db = next(f for f in azure_findings if f.rule_id == "AZ-DB-001")
        assert db.resource == "azurerm_postgresql_server.vuln_db"

    def test_all_findings_have_file(self, azure_findings: list[Finding]) -> None:
        for f in azure_findings:
            assert f.file != ""

    def test_all_findings_have_line(self, azure_findings: list[Finding]) -> None:
        for f in azure_findings:
            assert f.line > 0

    def test_all_findings_have_tags(self, azure_findings: list[Finding]) -> None:
        for f in azure_findings:
            assert "azure" in f.tags

    def test_all_findings_have_remediation(self, azure_findings: list[Finding]) -> None:
        for f in azure_findings:
            assert f.remediation is not None and len(f.remediation) > 0
