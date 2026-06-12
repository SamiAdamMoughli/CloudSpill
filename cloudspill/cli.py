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
def scan(
    path: str,
    output_format: str,
    min_severity: str,
    show_taint: bool,
    rules: str | None,
    fail_on: str | None,
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

    # Format output
    match output_format:
        case "table":
            TableFormatter(show_taint=show_taint).format(filtered, filtered_taint)
        case "json":
            click.echo(JsonFormatter().format(filtered, filtered_taint))
        case "markdown":
            click.echo(MarkdownFormatter().format(filtered, filtered_taint))

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


if __name__ == "__main__":
    scan()
