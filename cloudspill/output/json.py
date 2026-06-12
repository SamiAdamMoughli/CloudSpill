"""JSON output formatter."""

from __future__ import annotations

import json as json_lib
from typing import Any

from cloudspill.models.findings import Finding
from cloudspill.models.taint import TaintResult


class JsonFormatter:
    """Machine-readable JSON output."""

    def format(self, findings: list[Finding], taint_results: list[TaintResult]) -> str:
        output: dict[str, Any] = {
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "resource": f.resource,
                    "file": f.file,
                    "line": f.line,
                }
                for f in findings
            ],
            "taint_results": [
                {
                    "finding": tr.finding.rule_id,
                    "resource": tr.finding.resource,
                    "paths": [
                        {
                            "nodes": list(tp.nodes),
                            "edges": [e.value for e in tp.edges],
                            "risk": tp.risk,
                        }
                        for tp in tr.paths
                    ],
                }
                for tr in taint_results
            ],
            "summary": {
                "total_findings": len(findings),
                "taint_chains": len(taint_results),
            },
        }
        return json_lib.dumps(output, indent=2)
