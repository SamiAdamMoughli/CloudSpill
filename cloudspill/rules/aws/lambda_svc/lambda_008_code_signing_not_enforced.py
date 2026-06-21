"""LAMBDA-008: Function does not enforce code signing.

A ``code_signing_config_arn`` ties the function to a signing profile so Lambda
verifies the deployment package's signature before accepting it. That is the
control that stops tampered or unauthorized code from being deployed — a direct
supply-chain defence. Without it, anyone who can call ``UpdateFunctionCode`` can
ship arbitrary code.

This rule flags an ``aws_lambda_function`` with no ``code_signing_config_arn``.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register


@register
class LambdaCodeSigningNotEnforced:
    """LAMBDA-008: aws_lambda_function has no code_signing_config_arn."""

    rule_id = "LAMBDA-008"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_lambda_function":
            return []

        if str(node.attributes.get("code_signing_config_arn", "")).strip():
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Lambda function does not enforce code signing",
                description=(
                    "code_signing_config_arn is not set on this "
                    "aws_lambda_function, so deployment packages are not signature "
                    "-verified. Anyone able to update the code can ship tampered or "
                    "unauthorized packages."
                ),
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
                remediation=(
                    "Create an aws_lambda_code_signing_config bound to a Signer "
                    "profile and set code_signing_config_arn on the function."
                ),
                tags=frozenset(
                    {"lambda", "code-signing", "supply-chain", "integrity", "aws"}
                ),
            )
        ]
