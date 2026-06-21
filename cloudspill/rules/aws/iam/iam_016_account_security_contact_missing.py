"""IAM-016: Account security alternate contact is incomplete.

AWS lets you register a dedicated SECURITY alternate contact
(``aws_account_alternate_contact`` with ``alternate_contact_type = "SECURITY"``)
so abuse reports and security notifications reach the right people instead of the
root email. A SECURITY contact declared with missing fields (no email, name, or
phone) defeats the purpose — the notification path is effectively broken.

This per-resource rule flags a SECURITY ``aws_account_alternate_contact`` whose
``email_address``, ``name``, or ``phone_number`` is empty. (It cannot detect the
contact being absent entirely, which is a separate account-baseline gap.)
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_REQUIRED_FIELDS = ("name", "email_address", "phone_number")


@register
class IAMSecurityContactMissing:
    """IAM-016: SECURITY alternate contact has empty required fields."""

    rule_id = "IAM-016"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_account_alternate_contact":
            return []

        contact_type = (
            str(node.attributes.get("alternate_contact_type", "")).strip().upper()
        )
        if contact_type != "SECURITY":
            return []

        missing = [
            field
            for field in _REQUIRED_FIELDS
            if not str(node.attributes.get(field, "")).strip()
        ]
        if not missing:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Account security alternate contact is incomplete",
                description=(
                    "The SECURITY alternate contact is missing "
                    + ", ".join(missing)
                    + ". Security and abuse notifications may not reach anyone."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Provide name, email_address, and phone_number for the "
                    "SECURITY alternate contact (a monitored security distribution "
                    "list, not an individual)."
                ),
                tags=frozenset(
                    {"iam", "account-baseline", "security-contact", "governance", "aws"}
                ),
            )
        ]
