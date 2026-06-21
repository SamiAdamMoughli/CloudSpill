"""LAMBDA-003: Secret stored in a plaintext environment variable.

A function's ``environment.variables`` are stored with the function configuration
and are readable by anyone with ``lambda:GetFunctionConfiguration`` — and, unless
a CMK is set, encrypted only with an AWS-managed key. Putting a password, API
key, or token there leaks it to a much wider audience than intended; secrets
belong in Secrets Manager / SSM Parameter Store, fetched at runtime.

This rule flags an ``aws_lambda_function`` whose environment defines a variable
whose **name** looks secret-bearing and which carries an inline value.
"""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.aws.utils.hcl import as_blocks
from cloudspill.rules.base import register

_SECRET_HINTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "access_key",
    "accesskey",
    "private_key",
    "privatekey",
    "credential",
)


def _looks_secret(name: str) -> bool:
    lowered = name.replace("-", "_").lower()
    return any(hint in lowered for hint in _SECRET_HINTS)


@register
class LambdaSecretsInEnvVars:
    """LAMBDA-003: environment variable carries an inline secret value."""

    rule_id = "LAMBDA-003"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "aws_lambda_function":
            return []

        for env in as_blocks(node.attributes.get("environment")):
            variables = env.get("variables")
            if not isinstance(variables, dict):
                continue
            for name, value in variables.items():
                if _looks_secret(str(name)) and str(value).strip():
                    return [self._finding(node, str(name))]
        return []

    def _finding(self, node: IaCNode, var_name: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            title="Secret stored in a plaintext Lambda environment variable",
            description=(
                f"environment.variables sets '{var_name}' with an inline value. "
                "Lambda environment variables are stored with the function config "
                "and readable via GetFunctionConfiguration, exposing the secret."
            ),
            resource=node.node_id,
            file=node.source_file,
            line=node.line,
            remediation=(
                "Store the secret in Secrets Manager or SSM Parameter Store and "
                "fetch it at runtime; at minimum set a kms_key_arn to encrypt the "
                "environment with a CMK."
            ),
            tags=frozenset(
                {"lambda", "secrets", "plaintext-credentials", "aws"}
            ),
        )
