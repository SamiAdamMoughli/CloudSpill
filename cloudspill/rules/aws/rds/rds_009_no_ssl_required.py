"""RDS-009: Parameter group disables SSL/TLS enforcement.

In-transit encryption to RDS is enforced through a DB parameter group: PostgreSQL
uses ``rds.force_ssl = 1`` and MySQL/MariaDB use ``require_secure_transport = ON``.
A parameter group that sets one of these to a disabled value (``0`` / ``OFF``)
explicitly allows plaintext connections, so credentials and query data can be
read or tampered with by anyone able to intercept the network path.

This rule flags an ``aws_db_parameter_group`` or ``aws_rds_cluster_parameter_group``
that sets an SSL-enforcement parameter to a disabled value. (Absence of the
parameter relies on the engine default and is not flagged.)
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register

_PARAM_GROUP_TYPES = frozenset(
    {"aws_db_parameter_group", "aws_rds_cluster_parameter_group"}
)
_SSL_PARAMS = {"rds.force_ssl": {"0"}, "require_secure_transport": {"off", "0"}}


@register
class RDSNoSslRequired:
    """RDS-009: parameter group disables SSL enforcement."""

    rule_id = "RDS-009"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type not in _PARAM_GROUP_TYPES:
            return []

        params = as_blocks(node.attributes.get("parameter"))
        params += [c.attributes for c in node.children if c.resource_type == "parameter"]
        for param in params:
            name = str(param.get("name", "")).strip().lower()
            value = str(param.get("value", "")).strip().lower()
            if name in _SSL_PARAMS and value in _SSL_PARAMS[name]:
                return [self._finding(node, name, value)]
        return []

    def _finding(self, node: IaCNode, name: str, value: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="RDS parameter group disables SSL/TLS enforcement",
            description=(
                f"This parameter group sets {name} = {value}, allowing plaintext "
                "database connections. Credentials and query data can be "
                "intercepted or tampered with on the network path."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Set rds.force_ssl = 1 (PostgreSQL) or require_secure_transport = "
                "ON (MySQL/MariaDB) to require encrypted connections."
            ),
            tags=frozenset(
                {"rds", "ssl", "in-transit-encryption", "database", "aws"}
            ),
        )
