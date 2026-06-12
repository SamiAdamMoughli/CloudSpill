"""Markdown report formatter."""

from __future__ import annotations

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.taint import TaintResult


class MarkdownFormatter:
    """Markdown report output — suitable for file export or CI comments."""

    def format(self, findings: list[Finding], taint_results: list[TaintResult]) -> str:
        lines: list[str] = []
        lines.append("# CloudSpill — Scan Report\n")

        if not findings:
            lines.append("**No findings detected.**\n")
            return "\n".join(lines)

        # Findings table
        lines.append("## Findings\n")
        lines.append("| ID | Severity | Title | Resource | Location |")
        lines.append("|---|---|---|---|---|")

        sorted_findings = sorted(
            findings, key=lambda f: list(Severity).index(f.severity)
        )
        for f in sorted_findings:
            short = f.file.replace("\\", "/").split("/")
            path = "/".join(short[-2:]) if len(short) > 2 else f.file
            lines.append(
                f"| {f.rule_id} | {f.severity.value} | {f.title} | `{f.resource}` | `{path}:{f.line}` |"
            )

        # Taint analysis
        if taint_results:
            lines.append("\n## Taint Analysis\n")
            for tr in taint_results:
                lines.append(f"### {tr.finding.rule_id} — {tr.finding.resource}\n")
                for tp in tr.paths:
                    chain = " → ".join(f"`{n}`" for n in tp.nodes)
                    lines.append(f"- {chain}")
                    lines.append(f"  - *{tp.risk}*")
                lines.append("")

        # Summary
        counts = {s: 0 for s in Severity}
        for f in findings:
            counts[f.severity] += 1
        parts = [f"**{counts[s]} {s.value}**" for s in Severity if counts[s] > 0]
        chains = len(taint_results)
        lines.append(
            f"\n---\n**Summary:** {' | '.join(parts)} | {chains} taint chain{'s' if chains != 1 else ''}"
        )

        return "\n".join(lines)
