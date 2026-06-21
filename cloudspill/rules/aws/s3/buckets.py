"""Shared helpers for the S3 rule set.

Modern S3 configuration is split across many sibling resources
(``aws_s3_bucket_versioning``, ``aws_s3_bucket_server_side_encryption_configuration``,
``aws_s3_bucket_logging``, ``aws_s3_bucket_policy``, …), each referencing the
bucket by id. Several S3 rules therefore ask "is resource X attached to this
bucket?" via the graph, and a few scan an attached policy's statements. These
helpers centralize both, plus the bool/ACL normalization the rules share.

This module registers no rules; it is imported by the ``s3_*`` rule modules.
"""

from __future__ import annotations

from typing import Any

from cloudspill.models.graph import ResourceGraph
from cloudspill.models.nodes import IaCNode

PUBLIC_ACLS = frozenset({"public-read", "public-read-write"})


def is_true(value: Any) -> bool:
    if isinstance(value, bool):
        return value is True
    return str(value).strip().lower() == "true"


def has_attached(node: IaCNode, graph: ResourceGraph, *resource_types: str) -> bool:
    """True if a sibling resource of one of `resource_types` references the bucket."""
    for edge in graph.incoming(node.node_id):
        source = graph.get_node(edge.source)
        if source is not None and source.resource_type in resource_types:
            return True
    return False
