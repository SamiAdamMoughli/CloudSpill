"""CLI entry point — thin wrapper over ScanContext."""

from __future__ import annotations

from pathlib import Path

import click

from cloudspill.context import ScanConfig, ScanContext


@click.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "output_format", type=click.Choice(["table", "json", "markdown"]), default="table")
@click.option("--min-severity", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]), default="LOW")
@click.option("--show-taint", is_flag=True)
@click.option("--rules", default=None, help="Comma-separated rule sets: s3,iam,ec2,rds,docker")
@click.option("--fail-on", default=None, help="Exit 1 if findings at or above this severity")
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
    paths = list(target.rglob("*")) if target.is_dir() else [target]
    result = context.run(paths)

    # TODO: dispatch to the right Formatter based on output_format
    click.echo(f"Findings: {len(result.findings)}  |  Taint chains: {len(result.taint_results)}")


if __name__ == "__main__":
    scan()
