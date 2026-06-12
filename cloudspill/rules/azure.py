"""Azure security rules.

All rules use @register so they are auto-discovered by RuleRegistry.
Enable with: --rules az

| ID          | Resource type                       | Finding                                       | Severity |
|-------------|-------------------------------------|-----------------------------------------------|----------|
| AZ-STG-001  | azurerm_storage_account             | enable_https_traffic_only = false             | HIGH     |
| AZ-STG-002  | azurerm_storage_account             | allow_nested_items_to_be_public = true        | HIGH     |
| AZ-STG-003  | azurerm_storage_account             | min_tls_version below TLS1_2                  | MEDIUM   |
| AZ-STG-004  | azurerm_storage_container           | container_access_type = "container" or "blob" | CRITICAL |
| AZ-NSG-001  | azurerm_network_security_group      | SSH (port 22) open to *                       | CRITICAL |
| AZ-NSG-002  | azurerm_network_security_group      | Any port open to * inbound                    | HIGH     |
| AZ-VM-001   | azurerm_linux_virtual_machine       | disable_password_authentication = false       | HIGH     |
| AZ-VM-002   | azurerm_linux_virtual_machine       | Reachable via azurerm_public_ip (graph)       | MEDIUM   |
| AZ-DB-001   | azurerm_postgresql_server           | public_network_access_enabled = true          | CRITICAL |
| AZ-DB-002   | azurerm_postgresql_server           | ssl_enforcement_enabled = false               | HIGH     |
| AZ-DB-003   | azurerm_postgresql_firewall_rule    | start_ip_address = "0.0.0.0"                  | CRITICAL |
| AZ-RBAC-001 | azurerm_role_assignment             | Owner or Contributor role assigned            | CRITICAL |
| AZ-FUNC-001 | azurerm_linux_function_app          | https_only = false                            | HIGH     |
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_OPEN_SOURCES = frozenset({"*", "Internet", "0.0.0.0/0", "::/0"})
_PRIVILEGED_ROLES = frozenset({"Owner", "Contributor"})
_WEAK_TLS = frozenset({"TLS1_0", "TLS1_1"})
_PUBLIC_CONTAINER_ACCESS = frozenset({"container", "blob"})


def _get_security_rules(node: IaCNode) -> list[dict[str, Any]]:
    """Extract security_rule entries from an NSG node.

    python-hcl2 parses inline security_rule blocks as list[dict] stored
    in node.attributes. Falls back to child nodes for edge cases.
    """
    rules = node.attributes.get("security_rule", [])
    if isinstance(rules, list):
        return [r for r in rules if isinstance(r, dict)]
    if isinstance(rules, dict):
        return [rules]
    return [c.attributes for c in node.children if c.resource_type == "security_rule"]


def _is_open_inbound(rule: dict[str, Any]) -> bool:
    return (
        rule.get("direction", "").lower() == "inbound"
        and rule.get("access", "").lower() == "allow"
        and str(rule.get("source_address_prefix", "")).strip() in _OPEN_SOURCES
    )


# ─── Storage ─────────────────────────────────────────────────────────────────


@register
class AZStorageHttps:
    """AZ-STG-001: HTTPS-only traffic not enforced on storage account."""

    rule_id = "AZ-STG-001"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "azurerm_storage_account":
            return []
        if node.attributes.get("enable_https_traffic_only") is False:
            return [Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Storage account allows HTTP traffic",
                description=(
                    "enable_https_traffic_only is false. "
                    "Data in transit can be intercepted over unencrypted HTTP."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation="Set enable_https_traffic_only = true.",
                tags=frozenset({"storage", "encryption-in-transit", "azure"}),
            )]
        return []


@register
class AZStorageBlobPublic:
    """AZ-STG-002: Public blob access allowed on storage account."""

    rule_id = "AZ-STG-002"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "azurerm_storage_account":
            return []
        if node.attributes.get("allow_nested_items_to_be_public") is True:
            return [Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Storage account allows public blob access",
                description=(
                    "allow_nested_items_to_be_public is true. "
                    "Containers in this account can be made publicly readable."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation="Set allow_nested_items_to_be_public = false.",
                tags=frozenset({"storage", "public-access", "azure"}),
            )]
        return []


@register
class AZStorageWeakTLS:
    """AZ-STG-003: Storage account min TLS version below 1.2."""

    rule_id = "AZ-STG-003"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "azurerm_storage_account":
            return []
        tls = node.attributes.get("min_tls_version", "TLS1_2")
        if tls in _WEAK_TLS:
            return [Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title=f"Storage account accepts weak TLS ({tls})",
                description=(
                    f"min_tls_version is {tls}. "
                    "TLS 1.0 and 1.1 have known vulnerabilities and are deprecated."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation="Set min_tls_version = \"TLS1_2\".",
                tags=frozenset({"storage", "tls", "encryption-in-transit", "azure"}),
            )]
        return []


@register
class AZStorageContainerPublic:
    """AZ-STG-004: Storage container publicly accessible."""

    rule_id = "AZ-STG-004"
    severity = Severity.CRITICAL

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "azurerm_storage_container":
            return []
        access = node.attributes.get("container_access_type", "private")
        if access in _PUBLIC_CONTAINER_ACCESS:
            return [Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title=f"Storage container publicly accessible (access_type={access})",
                description=(
                    f"container_access_type is \"{access}\". "
                    "Blobs in this container are readable by anyone on the internet."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation="Set container_access_type = \"private\".",
                tags=frozenset({"storage", "public-access", "azure"}),
            )]
        return []


# ─── Network Security Groups ─────────────────────────────────────────────────


@register
class AZNSGSSHOpen:
    """AZ-NSG-001: NSG allows SSH (port 22) from any source."""

    rule_id = "AZ-NSG-001"
    severity = Severity.CRITICAL

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "azurerm_network_security_group":
            return []
        for rule in _get_security_rules(node):
            if not _is_open_inbound(rule):
                continue
            dest = str(rule.get("destination_port_range", ""))
            if dest in ("22", "*"):
                return [Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title="NSG allows SSH from 0.0.0.0/0",
                    description=(
                        "A security rule permits inbound TCP port 22 "
                        "from any source address. Exposes SSH to the internet."
                    ),
                    resource=node.node_id,
                    file=node.source_file,
                    line=node.line,
                    remediation=(
                        "Restrict source_address_prefix to a known CIDR "
                        "or use Azure Bastion for SSH access."
                    ),
                    tags=frozenset({"network", "ssh", "public-access", "azure"}),
                )]
        return []


@register
class AZNSGOpenIngress:
    """AZ-NSG-002: NSG allows unrestricted inbound traffic on any port."""

    rule_id = "AZ-NSG-002"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "azurerm_network_security_group":
            return []
        for rule in _get_security_rules(node):
            if not _is_open_inbound(rule):
                continue
            dest = str(rule.get("destination_port_range", ""))
            if dest in ("22", ""):
                continue  # covered by AZ-NSG-001 or empty rule
            return [Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title=f"NSG allows unrestricted inbound on port(s) {dest}",
                description=(
                    f"A security rule permits inbound traffic on port(s) {dest} "
                    "from any source address. Reduces network isolation."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation="Restrict source_address_prefix to a known CIDR.",
                tags=frozenset({"network", "public-access", "azure"}),
            )]
        return []


# ─── Virtual Machines ────────────────────────────────────────────────────────


@register
class AZVMPasswordAuth:
    """AZ-VM-001: Password authentication not disabled on Linux VM."""

    rule_id = "AZ-VM-001"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "azurerm_linux_virtual_machine":
            return []
        if node.attributes.get("disable_password_authentication") is False:
            return [Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Linux VM allows password authentication",
                description=(
                    "disable_password_authentication is false. "
                    "Password-based SSH login is susceptible to brute-force attacks."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set disable_password_authentication = true "
                    "and provision SSH public keys via admin_ssh_key blocks."
                ),
                tags=frozenset({"vm", "authentication", "azure"}),
            )]
        return []


@register
class AZVMPublicIP:
    """AZ-VM-002: Linux VM reachable via a public IP (graph traversal)."""

    rule_id = "AZ-VM-002"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "azurerm_linux_virtual_machine":
            return []

        # Walk outgoing edges up to 2 hops looking for azurerm_public_ip
        for edge in graph.outgoing(node.node_id):
            if self._is_public_ip(graph, edge.target):
                return self._finding(node)
            for edge2 in graph.outgoing(edge.target):
                if self._is_public_ip(graph, edge2.target):
                    return self._finding(node)

        return []

    @staticmethod
    def _is_public_ip(graph: ResourceGraph, node_id: str) -> bool:
        n = graph.get_node(node_id)
        return n is not None and n.resource_type == "azurerm_public_ip"

    def _finding(self, node: IaCNode) -> list[Finding]:
        return [Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Linux VM attached to a public IP",
            description=(
                "The VM's network path includes an azurerm_public_ip resource, "
                "making it directly reachable from the internet."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Remove the public IP and use a load balancer, NAT gateway, "
                "or Azure Bastion for access."
            ),
            tags=frozenset({"vm", "network", "public-access", "azure"}),
        )]


# ─── Databases ───────────────────────────────────────────────────────────────


@register
class AZPostgresPublicAccess:
    """AZ-DB-001: PostgreSQL server has public network access enabled."""

    rule_id = "AZ-DB-001"
    severity = Severity.CRITICAL

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "azurerm_postgresql_server":
            return []
        if node.attributes.get("public_network_access_enabled") is True:
            return [Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="PostgreSQL server publicly accessible",
                description=(
                    "public_network_access_enabled is true. "
                    "The database endpoint is reachable from the internet."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Set public_network_access_enabled = false "
                    "and use VNet service endpoints or Private Link."
                ),
                tags=frozenset({"database", "public-access", "azure"}),
            )]
        return []


@register
class AZPostgresNoSSL:
    """AZ-DB-002: SSL not enforced on PostgreSQL server."""

    rule_id = "AZ-DB-002"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "azurerm_postgresql_server":
            return []
        if node.attributes.get("ssl_enforcement_enabled") is False:
            return [Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="PostgreSQL server does not enforce SSL",
                description=(
                    "ssl_enforcement_enabled is false. "
                    "Database connections can be made without TLS encryption."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation="Set ssl_enforcement_enabled = true.",
                tags=frozenset({"database", "encryption-in-transit", "azure"}),
            )]
        return []


@register
class AZPostgresFirewallOpen:
    """AZ-DB-003: PostgreSQL firewall rule allows all IP addresses."""

    rule_id = "AZ-DB-003"
    severity = Severity.CRITICAL

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "azurerm_postgresql_firewall_rule":
            return []
        if node.attributes.get("start_ip_address") == "0.0.0.0":
            return [Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="PostgreSQL firewall rule allows all IPs (0.0.0.0)",
                description=(
                    "start_ip_address is 0.0.0.0, opening the database firewall "
                    "to all internet traffic."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Restrict start_ip_address and end_ip_address to known "
                    "application or VNet CIDRs."
                ),
                tags=frozenset({"database", "network", "public-access", "azure"}),
            )]
        return []


# ─── RBAC ─────────────────────────────────────────────────────────────────────


@register
class AZRBACOverPrivileged:
    """AZ-RBAC-001: Owner or Contributor role assigned."""

    rule_id = "AZ-RBAC-001"
    severity = Severity.CRITICAL

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "azurerm_role_assignment":
            return []
        role = node.attributes.get("role_definition_name", "")
        if role not in _PRIVILEGED_ROLES:
            return []
        scope = str(node.attributes.get("scope", ""))
        # Flag subscription-scope assignments (highest blast radius).
        # Resource-group-scope is less severe but still flagged at CRITICAL
        # since Owner/Contributor anywhere is dangerous.
        return [Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title=f"Overprivileged role assignment: {role}",
            description=(
                f"Role \"{role}\" grants broad write/delete permissions. "
                f"Scope: {scope or 'unknown'}. "
                "Compromised identity has full control over the target scope."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Apply least-privilege: use a built-in role with only the "
                "permissions required (e.g. Storage Blob Data Reader) "
                "and scope to the narrowest resource."
            ),
            tags=frozenset({"iam", "rbac", "privilege-escalation", "azure"}),
        )]


# ─── Function Apps ────────────────────────────────────────────────────────────


@register
class AZFunctionAppHttps:
    """AZ-FUNC-001: Azure Function App allows HTTP (https_only = false)."""

    rule_id = "AZ-FUNC-001"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "azurerm_linux_function_app":
            return []
        if node.attributes.get("https_only") is False:
            return [Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Function App allows unencrypted HTTP traffic",
                description=(
                    "https_only is false. HTTP requests are not automatically "
                    "redirected to HTTPS, exposing data in transit."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation="Set https_only = true.",
                tags=frozenset({"serverless", "encryption-in-transit", "azure"}),
            )]
        return []
