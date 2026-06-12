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
_RULE_CHOICES = "s3,iam,ec2,rds,docker,az"

_PROVIDER_DEFAULT_MODELS: dict[str, str] = {
    "local": "qwen3.6-35b-a3b",
    "openai": "gpt-4o",
    "anthropic": "claude-haiku-4-5-20251001",
    "google": "gemini-3.5-flash",
}


def _default_model(provider: str) -> str:
    return _PROVIDER_DEFAULT_MODELS.get(provider, "qwen3.6-35b-a3b")


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
    "--graph", "show_graph", is_flag=True,
    help=(
        "Output a Mermaid diagram of the resource graph, findings, and "
        "taint paths. Paste into https://mermaid.live or a GitHub markdown "
        "code block (```mermaid)."
    ),
)
@click.option(
    "--graph-file", default=None,
    type=click.Path(writable=True),
    help="Write the Mermaid diagram to FILE instead of stdout.",
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
    help="Enrich findings with an LLM (local or cloud, see --provider)",
)
@click.option(
    "--prompt-mode",
    type=click.Choice(["explain", "fix", "triage"]),
    default="explain",
    help=(
        "Prompt template to use with --ai: "
        "explain=plain-English risk (default), "
        "fix=remediation snippet, "
        "triage=true/false-positive assessment"
    ),
)
@click.option(
    "--provider",
    type=click.Choice(["local", "openai", "anthropic", "google"]),
    default="local",
    help=(
        "LLM backend: local=Ollama/vLLM (default), "
        "openai=OpenAI API, anthropic=Anthropic API, "
        "google=Gemini API"
    ),
)
@click.option("--model", default=None, help="Model tag (provider-specific default if omitted)")
@click.option(
    "--timeout", default=120, show_default=True,
    help="Request timeout in seconds for --provider local (increase for slow hardware)",
)
@click.option(
    "--ai-url", default="http://localhost:11434/v1",
    help="Base URL for local inference server (--provider local only)",
)
@click.option(
    "--api-key", default=None, envvar="CLOUDSPILL_API_KEY",
    help="API key for --provider openai, anthropic, or google (or set CLOUDSPILL_API_KEY)",
)
@click.option(
    "--ai-rpm", default=None, type=int,
    help=(
        "Max LLM requests per minute (e.g. 9 for Gemini free tier). "
        "Unset = unlimited (parallel). Use when hitting 429s."
    ),
)
def scan(
    path: str,
    output_format: str,
    min_severity: str,
    show_taint: bool,
    show_graph: bool,
    graph_file: str | None,
    rules: str | None,
    fail_on: str | None,
    ai: bool,
    prompt_mode: str,
    provider: str,
    model: str | None,
    timeout: int,
    ai_url: str,
    api_key: str | None,
    ai_rpm: int | None,
) -> None:
    """CloudSpill — scan infrastructure code for structural misconfigurations."""
    rule_sets = set(rules.split(",")) if rules else None

    # Resolve model default per provider
    _model = model or _default_model(provider)

    config = ScanConfig(
        rule_sets=rule_sets,
        min_severity=min_severity,
        show_taint=show_taint,
        fail_on=fail_on,
        enrichment=EnrichmentConfig(enabled=ai, model=_model, base_url=ai_url),
    )

    context = ScanContext(config)

    if ai:
        from cloudspill.enrichers.ai import AIEnricher  # noqa: PLC0415
        from cloudspill.enrichers.providers import make_provider  # noqa: PLC0415
        try:
            llm_provider = make_provider(
                provider,
                model=_model,
                base_url=ai_url,
                api_key=api_key,
                timeout=timeout,
            )
        except ValueError as exc:
            raise click.UsageError(str(exc)) from exc
        _PROVIDER_NAME_MAP = {"google": "gemini", "anthropic": "claude"}
        context.add_enricher(
            AIEnricher(
                model=_model,
                base_url=ai_url,
                provider=llm_provider,
                mode=prompt_mode,
                rpm_limit=ai_rpm,
                provider_name=_PROVIDER_NAME_MAP.get(provider, "default"),
            )
        )
        click.echo(f"Enriching with {provider}/{_model} [{prompt_mode}]...\n")

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

    if show_graph or graph_file:
        from cloudspill.output.graph import MermaidGraphFormatter  # noqa: PLC0415
        gf = MermaidGraphFormatter()
        diagram = gf.format(result.graph, filtered.findings, filtered.taint_results)
        summary = gf.format_summary(
            result.graph, filtered.findings, filtered.taint_results
        )
        if graph_file:
            Path(graph_file).write_text(diagram, encoding="utf-8")
            click.echo(f"Graph written to {graph_file}  ({summary})")
        else:
            click.echo("\n```mermaid")
            click.echo(diagram, nl=False)
            click.echo("```")
            click.echo(f"\n{summary}")

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
