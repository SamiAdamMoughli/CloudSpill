"""CLOUDFRONT-002: CloudFront distribution allows a TLS version below 1.2.

The viewer TLS floor is set by ``minimum_protocol_version`` inside the
``viewer_certificate`` block. Only the ``TLSv1.2_*`` family (``TLSv1.2_2018``,
``TLSv1.2_2019``, ``TLSv1.2_2021``) is considered safe; SSLv3, TLSv1,
``TLSv1_2016`` and ``TLSv1.1_2016`` have known weaknesses and are deprecated.

Two cases are flagged:

1. ``minimum_protocol_version`` is present but not a ``TLSv1.2`` value.
2. ``cloudfront_default_certificate = true`` — the default ``*.cloudfront.net``
   certificate forces a TLSv1 floor and ignores ``minimum_protocol_version``,
   so it cannot enforce TLS 1.2.

A ``viewer_certificate`` that supplies a custom cert (ACM/IAM) and a
``TLSv1.2`` minimum is clean. A missing ``minimum_protocol_version`` on a
custom cert is left unjudged to avoid false positives on partial configs.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

_SECURE_TLS_PREFIX = "tlsv1.2"
_CERT_KEY = "viewer_certificate"


@register
class CloudFrontTlsVersionLow:
    """CLOUDFRONT-002: viewer_certificate permits TLS below 1.2."""

    rule_id = "CLOUDFRONT-002"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_cloudfront_distribution":
            return []

        for cert in self._cert_blocks(node):
            if cert.get("cloudfront_default_certificate") is True:
                return [
                    self._finding(
                        node,
                        detail=(
                            "cloudfront_default_certificate is true. The default "
                            "*.cloudfront.net certificate enforces only a TLSv1 "
                            "floor and ignores minimum_protocol_version."
                        ),
                    )
                ]

            version = str(cert.get("minimum_protocol_version", "")).strip().lower()
            if version and not version.startswith(_SECURE_TLS_PREFIX):
                return [
                    self._finding(
                        node,
                        detail=(
                            f"minimum_protocol_version is "
                            f"'{cert.get('minimum_protocol_version')}', which permits "
                            "TLS versions below 1.2."
                        ),
                    )
                ]
        return []

    @staticmethod
    def _cert_blocks(node: IaCNode) -> list[dict[str, Any]]:
        """Collect viewer_certificate blocks regardless of how hcl2 shaped them."""
        blocks: list[dict[str, Any]] = []
        value = node.attributes.get(_CERT_KEY)
        if isinstance(value, list):
            blocks.extend(b for b in value if isinstance(b, dict))
        elif isinstance(value, dict):
            blocks.append(value)
        blocks.extend(
            c.attributes for c in node.children if c.resource_type == _CERT_KEY
        )
        return blocks

    def _finding(self, node: IaCNode, detail: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="CloudFront distribution allows TLS below 1.2",
            description=detail,
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Supply a custom ACM/IAM certificate and set "
                "minimum_protocol_version to a TLSv1.2 value (e.g. TLSv1.2_2021)."
            ),
            tags=frozenset(
                {"cloudfront", "tls", "encryption-in-transit", "aws"}
            ),
        )
