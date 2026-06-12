"""CLI entry point — thin wrapper over ScanContext."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from cloudspill.context import ScanConfig, ScanContext
from cloudspill.models.findings import Severity
from cloudspill.output.json import JsonFormatter
from cloudspill.output.markdown import MarkdownFormatter
from cloudspill.output.table import TableFormatter


@click.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "output_format", type=click.Choice(["table", "json", "markdown"]), default="table")
@click.option("--min-severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), default="LOW")
@click.option("--show-taint", is_flag=True, help="Display taint propagation paths")
@click.option("--rules", default=None, help="Comma-separated rule sets: s3,iam,ec2,rds,docker")
@click.option("--fail-on", default=None, type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
              help="Exit code 1 if findings at or above this severity")
@click.option("--ai", is_flag=True, help="Enrich findings with Qwen3.6/Gemma 4 reasoning analysis")
@click.option("--model", default="qwen3.6-35b-a3b", help="Local model tag to target")
@click.option("--ai-url", default="http://localhost:11434/v1", help="Base URL for the local inference server")
def scan(
    path: str,
    output_format: str,
    min_severity: str,
    show_taint: bool,
    rules: str | None,
    fail_on: str | None,
    ai: bool,
    model: str,
    ai_url: str,
) -> None:
    """CloudSpill — scan infrastructure code for structural misconfigurations."""
    rule_sets = set(rules.split(",")) if rules else None
    config = ScanConfig(
        rule_sets=rule_sets,
        min_severity=min_severity,
        show_taint=show_taint,
        fail_on=fail_on,
    )

    context = ScanContext(config)
    target = Path(path)
    paths = _collect_files(target)

    if not paths:
        click.echo("No scannable files found (.tf, Dockerfile).")
        return

    result = context.run(paths)

    # Filter by minimum severity
    severity_order = list(Severity)
    min_idx = severity_order.index(Severity(min_severity))
    filtered = [f for f in result.findings if severity_order.index(f.severity) <= min_idx]
    filtered_taint = [t for t in result.taint_results if severity_order.index(t.finding.severity) <= min_idx]

    # AI enrichment
    enrichments: list[dict] = []
    if ai:
        from cloudspill.enrichers.ai import AIEnricher

        click.echo(f"🤖 Enriching with {model}...\n")
        enricher = AIEnricher(model=model, base_url=ai_url)
        enrichments = enricher.enrich(filtered, filtered_taint, result.graph)

    # Format output
    match output_format:
        case "table":
            TableFormatter(show_taint=show_taint).format(filtered, filtered_taint)
            if enrichments:
                _print_enrichments(enrichments)
        case "json":
            output = JsonFormatter().format(filtered, filtered_taint)
            if enrichments:
                import json
                parsed = json.loads(output)
                parsed["ai_enrichments"] = enrichments
                output = json.dumps(parsed, indent=2)
            click.echo(output)
        case "markdown":
            output = MarkdownFormatter().format(filtered, filtered_taint)
            if enrichments:
                output += _markdown_enrichments(enrichments)
            click.echo(output)

    # Exit code for CI/CD
    if fail_on:
        fail_idx = severity_order.index(Severity(fail_on))
        if any(severity_order.index(f.severity) <= fail_idx for f in filtered):
            sys.exit(1)


def _collect_files(target: Path) -> list[Path]:
    """Collect all scannable files from a path."""
    if target.is_file():
        return [target]
    files: list[Path] = []
    for p in target.rglob("*"):
        if p.is_file() and (p.suffix == ".tf" or p.name.lower().startswith("dockerfile")):
            files.append(p)
    return sorted(files)


def _print_enrichments(enrichments: list[dict]) -> None:
    """Print AI enrichments to the terminal via Rich."""
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel

    console = Console()
    console.print()
    console.print("[bold]🤖 AI Analysis[/bold]")

    for e in enrichments:
        if "[AI unavailable]" in e.get("explanation", ""):
            console.print(f"\n[dim]{e['rule_id']} @ {e['resource']}: {e['explanation']}[/dim]")
            continue

        content = f"**{e['rule_id']}** — `{e['resource']}`\n\n"
        content += e.get("explanation", "") + "\n\n"
        content += "**Suggested fix:**\n" + e.get("fix", "")

        console.print(Panel(Markdown(content), border_style="cyan"))


def _markdown_enrichments(enrichments: list[dict]) -> str:
    """Append AI enrichments to a markdown report."""
    lines = ["\n\n## AI Analysis\n"]
    for e in enrichments:
        if "[AI unavailable]" in e.get("explanation", ""):
            continue
        lines.append(f"### {e['rule_id']} — `{e['resource']}`\n")
        lines.append(e.get("explanation", "") + "\n")
        lines.append(f"**Fix:**\n\n{e.get('fix', '')}\n")
    return "\n".join(lines)


if __name__ == "__main__":
    scan()
