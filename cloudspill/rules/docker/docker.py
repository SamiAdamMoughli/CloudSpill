"""Dockerfile security rules.

| ID         | Finding                                      | Severity |
|------------|----------------------------------------------|----------|
| DOCKER-001 | USER root or no USER instruction             | HIGH     |
| DOCKER-003 | latest tag on base image                     | MEDIUM   |
| DOCKER-004 | Secret in ENV instruction                    | CRITICAL |
| DOCKER-005 | ADD used instead of COPY                     | LOW      |
| DOCKER-006 | Multiple RUN instructions that could chain   | INFO     |
"""

from __future__ import annotations

import re

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode
from cloudspill.rules.base import register

# Patterns that suggest a secret in an ENV value
_SECRET_PATTERNS = [
    re.compile(
        r"(?i)(password|passwd|secret|token|api_key|apikey|access_key|private_key)"
    ),
    re.compile(
        r"(?i)^(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|DATABASE_URL|DB_PASSWORD)$"
    ),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key ID pattern
]


def _looks_like_secret(key: str, value: str) -> bool:
    """Heuristic: does this ENV entry look like it holds a secret?"""
    for pattern in _SECRET_PATTERNS:
        if pattern.search(key):
            return True
    # Check for AWS key patterns in value
    if re.search(r"AKIA[0-9A-Z]{16}", value):
        return True
    # Connection strings with credentials
    if re.search(r"://\w+:\w+@", value):
        return True
    return False


@register
class DockerRootUser:
    """DOCKER-001: USER root or no USER instruction."""

    rule_id = "DOCKER-001"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        # This rule needs to see ALL instructions, not just one node.
        # We fire on the last FROM node if no USER instruction follows it,
        # or if USER is explicitly "root".
        if node.resource_type == "USER":
            user = node.attributes.get("user", "")
            if user.lower() == "root":
                return [
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title="Container runs as root",
                        description="Explicit USER root instruction. Container processes run with full privileges.",
                        resource=node.node_id,
                        file=node.source_file,
                        line=node.line,
                    )
                ]
        return []


@register
class DockerNoUserInstruction:
    """DOCKER-001b: No USER instruction in Dockerfile (whole-file check).

    This is a supplementary check that runs against FROM nodes and checks
    if any USER instruction exists in the same file by scanning the graph.
    """

    rule_id = "DOCKER-001"
    severity = Severity.HIGH

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "FROM":
            return []

        # Check all nodes in graph for a USER instruction in the same file
        for other in graph.nodes.values():
            if other.resource_type == "USER" and other.source_file == node.source_file:
                return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="No USER instruction — runs as root",
                description="Dockerfile has no USER instruction. Container defaults to running as root.",
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
            )
        ]


@register
class DockerLatestTag:
    """DOCKER-003: latest tag on base image."""

    rule_id = "DOCKER-003"
    severity = Severity.MEDIUM

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "FROM":
            return []
        tag = node.attributes.get("tag", "")
        if tag == "latest" or tag == "":
            return [
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title="Base image uses latest tag",
                    description=f"Image '{node.attributes.get('image', '?')}' uses the 'latest' tag. Builds are not reproducible.",
                    resource=node.node_id,
                    file=node.source_file,
                    line=node.line,
                )
            ]
        return []


@register
class DockerSecretInEnv:
    """DOCKER-004: Secret in ENV instruction."""

    rule_id = "DOCKER-004"
    severity = Severity.CRITICAL

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "ENV":
            return []

        findings: list[Finding] = []
        for key, value in node.attributes.items():
            if _looks_like_secret(key, str(value)):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        title=f"Secret in ENV: {key}",
                        description=f"ENV variable '{key}' appears to contain a secret. Secrets in ENV are baked into image layers.",
                        resource=node.node_id,
                        file=node.source_file,
                        line=node.line,
                    )
                )
        return findings


@register
class DockerAddInsteadOfCopy:
    """DOCKER-005: ADD used instead of COPY."""

    rule_id = "DOCKER-005"
    severity = Severity.LOW

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        if node.resource_type != "ADD":
            return []

        src = node.attributes.get("src", "")
        # ADD is acceptable for URLs and tar extraction
        if src.startswith("http") or src.endswith((".tar", ".tar.gz", ".tgz")):
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="ADD used instead of COPY",
                description="ADD has implicit tar extraction and URL fetch. Use COPY for simple file copying.",
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
            )
        ]


@register
class DockerUnchainedRun:
    """DOCKER-006: Multiple consecutive RUN instructions that could be chained."""

    rule_id = "DOCKER-006"
    severity = Severity.INFO

    def check(self, node: IaCNode, graph: ResourceGraph) -> list[Finding]:
        # This is a whole-file concern — we fire on the first RUN
        # if there are 3+ consecutive RUN nodes in the graph for this file.
        if node.resource_type != "RUN":
            return []

        # Collect all RUN nodes from this file, ordered by line
        run_nodes = sorted(
            [
                n
                for n in graph.nodes.values()
                if n.resource_type == "RUN" and n.source_file == node.source_file
            ],
            key=lambda n: n.line,
        )

        if len(run_nodes) < 3:
            return []

        # Only fire once — on the first RUN node
        if node.node_id != run_nodes[0].node_id:
            return []

        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title="Multiple RUN instructions could be chained",
                description=f"{len(run_nodes)} RUN instructions detected. Chain with && to reduce image layers.",
                resource=node.node_id,
                file=node.source_file,
                line=node.line,
            )
        ]
