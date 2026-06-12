"""Rich table output formatter."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.tree import Tree

from cloudspill.models.findings import Finding, Severity
from cloudspill.models.taint import TaintResult

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


class TableFormatter:
    """Rich terminal table output."""

    def __init__(self, show_taint: bool = False) -> None:
        self._show_taint = show_taint
        self._console = Console()

    def format(self, findings: list[Finding], taint_results: list[TaintResult]) -> str:
        """Format and print findings as a Rich table. Returns summary string."""
        if not findings:
            self._console.print("[green]No findings detected.[/green]")
            return "No findings detected."

        table = Table(title="CloudSpill — Scan Results", show_lines=True)
        table.add_column("ID", style="bold", width=12)
        table.add_column("Severity", width=10)
        table.add_column("Title", min_width=30)
        table.add_column("Resource", min_width=25)
        table.add_column("File:Line", min_width=15)

        sorted_findings = sorted(
            findings, key=lambda f: list(Severity).index(f.severity)
        )

        for f in sorted_findings:
            color = _SEVERITY_COLORS.get(f.severity, "white")
            table.add_row(
                f.rule_id,
                f"[{color}]{f.severity.value}[/{color}]",
                f.title,
                f.resource,
                f"{_short_path(f.file)}:{f.line}",
            )

        self._console.print(table)

        if self._show_taint and taint_results:
            self._console.print()
            self._console.print("[bold]Taint Analysis[/bold]")
            for tr in taint_results:
                color = _SEVERITY_COLORS.get(tr.finding.severity, "white")
                tree = Tree(
                    f"[{color}]{tr.finding.rule_id}[/{color}] {tr.finding.resource}"
                )
                for tp in tr.paths:
                    chain = " → ".join(tp.nodes[1:])
                    tree.add(f"[dim]└──[/dim] {chain}")
                    tree.add(f"    [italic]{tp.risk}[/italic]")
                self._console.print(tree)

        summary = _build_summary(findings, taint_results)
        self._console.print()
        self._console.print(summary)
        return summary


def _short_path(path: str) -> str:
    """Shorten file path for display."""
    parts = path.replace("\\", "/").split("/")
    return "/".join(parts[-2:]) if len(parts) > 2 else path


def _build_summary(findings: list[Finding], taint_results: list[TaintResult]) -> str:
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    parts = [f"{counts[s]} {s.value}" for s in Severity if counts[s] > 0]
    chains = len(taint_results)
    return f"Summary: {' | '.join(parts)} | {chains} taint chain{'s' if chains != 1 else ''} detected"
