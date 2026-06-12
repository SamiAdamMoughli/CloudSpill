"""CLI entry point — thin wrapper over ScanContext."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from cloudspill.context import EnrichmentConfig, ScanConfig, ScanContext
from cloudspill.models.findings import Severity
from cloudspill.output.json import JsonFormatter
from cloudspill.output.markdown import MarkdownFormatter
from cloudspill.output.table import TableFormatter

_SEVERITY_CHOICES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_FORMAT_CHOICES = ["table", "json", "markdown"]
_RULE_CHOICES = "s3,iam,ec2,rds,docker"


@click.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format", "output_format",
    type=click.Choice(_FORMAT_CHOICES),
    default="table",
)
@click.option(
    "--min-severity",
    type=click.Choice(_SEVERITY_CHOICES),
    default="LOW",
)
@click.option(
    "--show-taint", is_flag=True,
    help="Display taint propagation paths",
)
@click.option(
    "--rules", default=None,
    help=f"Comma-separated rule sets: {_RULE_CHOICES}",
)
@click.option(
    "--fail-on", default=None,
    type=click.Choice(_SEVERITY_CHOICES),
    help="Exit code 1 if findings at or above this severity",
)
@click.option(
    "--ai", is_flag=True,
    help="Enrich findings with local LLM analysis",
)
@click.option("--model", default="qwen3.6-35b-a3b", help="Local model tag")
@click.option(
    "--ai-url", default="http://localhost:11434/v1",
    help="Base URL for the local inference server",
)
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
        enrichment=EnrichmentConfig(enabled=ai, model=model, base_url=ai_url),
    )

    context = ScanContext(config)

    if ai:
        from cloudspill.enrichers.ai import AIEnricher  # noqa: PLC0415
        context.add_enricher(AIEnricher(model=model, base_url=ai_url))
        click.echo(f"Enriching with {model}...\n")

    target = Path(path)
    paths = _collect_files(target)

    if not paths:
        click.echo("No scannable files found (.tf, Dockerfile).")
        return

    result = context.run(paths)

    for err in result.metadata.parse_errors:
        click.echo(f"[warn] parse error in {err.file}: {err.message}", err=True)

    filtered = result.filter(min_severity)

    match output_format:
        case "table":
            TableFormatter(show_taint=show_taint).format(
                filtered.findings, filtered.taint_results
            )
            if filtered.enriched_findings:
                _print_enrichments(filtered.enriched_findings)
        case "json":
            import json as json_lib
            output = JsonFormatter().format(
                filtered.findings, filtered.taint_results
            )
            if filtered.enriched_findings:
                parsed = json_lib.loads(output)
                parsed["ai_enrichments"] = [
                    {
                        "rule_id": e.finding.rule_id,
                        "resource": e.finding.resource,
                        "explanation": e.explanation,
                        "fix": e.remediation_patch,
                        "confidence": e.confidence,
                        "model": e.model,
                    }
                    for e in filtered.enriched_findings
                ]
                output = json_lib.dumps(parsed, indent=2)
            click.echo(output)
        case "markdown":
            output = MarkdownFormatter().format(
                filtered.findings, filtered.taint_results
            )
            if filtered.enriched_findings:
                output += _markdown_enrichments(filtered.enriched_findings)
            click.echo(output)

    if fail_on:
        severity_order = list(Severity)
        fail_idx = severity_order.index(Severity(fail_on))
        if any(
            severity_order.index(f.severity) <= fail_idx
            for f in filtered.findings
        ):
            sys.exit(1)


def _collect_files(target: Path) -> list[Path]:
    """Collect all scannable files from a path."""
    if target.is_file():
        return [target]
    files: list[Path] = []
    for p in target.rglob("*"):
        if p.is_file() and (
            p.suffix == ".tf" or p.name.lower().startswith("dockerfile")
        ):
            files.append(p)
    return sorted(files)


def _print_enrichments(enriched: list) -> None:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel

    console = Console()
    console.print()
    console.print("[bold]AI Analysis[/bold]")

    for e in enriched:
        content = (
            f"**{e.finding.rule_id}** — `{e.finding.resource}`\n\n"
            f"{e.explanation}\n\n"
            f"**Suggested fix:**\n{e.remediation_patch}"
        )
        console.print(Panel(Markdown(content), border_style="cyan"))


def _markdown_enrichments(enriched: list) -> str:
    lines = ["\n\n## AI Analysis\n"]
    for e in enriched:
        lines.append(f"### {e.finding.rule_id} — `{e.finding.resource}`\n")
        lines.append(e.explanation + "\n")
        lines.append(f"**Fix:**\n\n{e.remediation_patch}\n")
    return "\n".join(lines)


if __name__ == "__main__":
    scan()
