"""CLI entry point — thin wrapper over ScanContext."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import click

from cloudspill.context import ScanConfig, ScanContext, ScanResult
from cloudspill.logging_config import configure_logging
from cloudspill.models.findings import Finding, Severity
from cloudspill.output.base import Formatter
from cloudspill.output.json import JsonFormatter
from cloudspill.output.markdown import MarkdownFormatter
from cloudspill.output.table import TableFormatter

if TYPE_CHECKING:
    from cloudspill.enrichers.types import EnrichedFinding

logger = logging.getLogger(__name__)

_SEVERITY_CHOICES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_FORMAT_CHOICES = ["table", "json", "markdown"]
_RULE_CHOICES = "s3,iam,ec2,rds,docker,az"

_PROVIDER_DEFAULT_MODELS: dict[str, str] = {
    "local": "qwen3.6-35b-a3b",
    "openai": "gpt-4o",
    "anthropic": "claude-haiku-4-5-20251001",
    "google": "gemini-3.5-flash",
}

# Maps a provider to its prompt-template subfolder (see enrichers/prompts/).
_PROVIDER_PROMPT_DIRS = {"google": "gemini", "anthropic": "claude"}


def _default_model(provider: str) -> str:
    return _PROVIDER_DEFAULT_MODELS.get(provider, "qwen3.6-35b-a3b")


@click.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(_FORMAT_CHOICES),
    default="table",
)
@click.option(
    "--min-severity",
    type=click.Choice(_SEVERITY_CHOICES),
    default="LOW",
)
@click.option(
    "--show-taint",
    is_flag=True,
    help="Display taint propagation paths",
)
@click.option(
    "--graph",
    "show_graph",
    is_flag=True,
    help=(
        "Output a Mermaid diagram of the resource graph, findings, and "
        "taint paths. Paste into https://mermaid.live or a GitHub markdown "
        "code block (```mermaid)."
    ),
)
@click.option(
    "--graph-file",
    default=None,
    type=click.Path(writable=True),
    help="Write the Mermaid diagram to FILE instead of stdout.",
)
@click.option(
    "--rules",
    default=None,
    help=f"Comma-separated rule sets: {_RULE_CHOICES}",
)
@click.option(
    "--fail-on",
    default=None,
    type=click.Choice(_SEVERITY_CHOICES),
    help="Exit code 1 if findings at or above this severity",
)
@click.option(
    "--ai",
    is_flag=True,
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
@click.option(
    "--model", default=None, help="Model tag (provider-specific default if omitted)"
)
@click.option(
    "--timeout",
    default=120,
    show_default=True,
    help="Request timeout in seconds for --provider local (increase for slow hardware)",
)
@click.option(
    "--ai-url",
    default="http://localhost:11434/v1",
    help="Base URL for local inference server (--provider local only)",
)
@click.option(
    "--api-key",
    default=None,
    envvar="CLOUDSPILL_API_KEY",
    help="API key for --provider openai, anthropic, or google (or set CLOUDSPILL_API_KEY)",
)
@click.option(
    "--ai-rpm",
    default=None,
    type=int,
    help=(
        "Max LLM requests per minute (e.g. 9 for Gemini free tier). "
        "Unset = unlimited (parallel). Use when hitting 429s."
    ),
)
@click.option(
    "-v",
    "--verbose",
    count=True,
    help="Increase log verbosity to stderr (-v INFO, -vv DEBUG).",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable DEBUG logging and full tracebacks on error.",
)
def scan(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
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
    verbose: int,
    debug: bool,
) -> None:
    """CloudSpill — scan infrastructure code for structural misconfigurations."""
    configure_logging(verbose, debug=debug)

    config = ScanConfig(
        rule_sets=set(rules.split(",")) if rules else None,
        min_severity=min_severity,
        show_taint=show_taint,
        fail_on=fail_on,
    )
    context = ScanContext(config)

    resolved_model = model or _default_model(provider)
    if ai:
        _attach_enricher(
            context,
            provider,
            resolved_model,
            ai_url,
            api_key,
            timeout,
            prompt_mode,
            ai_rpm,
        )

    paths = _collect_files(Path(path))
    if not paths:
        logger.warning("No scannable files found (.tf, Dockerfile) under %s", path)
        return

    try:
        result = context.run(paths)
    except Exception as exc:  # pylint: disable=broad-except
        logger.error("Scan failed: %s", exc)
        if debug:
            raise
        raise click.ClickException(
            f"Scan failed: {exc}. Re-run with --debug for a full traceback."
        ) from exc

    for err in result.metadata.parse_errors:
        logger.warning("Parse error in %s: %s", err.file, err.message)

    filtered = result.filter(min_severity)
    _emit_results(filtered, output_format, show_taint)

    if show_graph or graph_file:
        _emit_graph(result, filtered, graph_file)

    if fail_on and _has_blocking_finding(filtered.findings, fail_on):
        sys.exit(1)


def _attach_enricher(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    context: ScanContext,
    provider: str,
    model: str,
    ai_url: str,
    api_key: str | None,
    timeout: int,
    prompt_mode: str,
    ai_rpm: int | None,
) -> None:
    """Build the configured LLM provider and register it on the context."""
    from cloudspill.enrichers.ai import AIEnricher  # noqa: PLC0415
    from cloudspill.enrichers.providers import make_provider  # noqa: PLC0415

    try:
        llm_provider = make_provider(
            provider, model=model, base_url=ai_url, api_key=api_key, timeout=timeout
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc

    context.add_enricher(
        AIEnricher(
            model=model,
            base_url=ai_url,
            provider=llm_provider,
            mode=prompt_mode,
            rpm_limit=ai_rpm,
            provider_name=_PROVIDER_PROMPT_DIRS.get(provider, "default"),
        )
    )
    logger.info("Enriching with %s/%s [%s]", provider, model, prompt_mode)


def _emit_results(result: ScanResult, output_format: str, show_taint: bool) -> None:
    """Render findings to stdout in the requested format."""
    match output_format:
        case "table":
            table: Formatter = TableFormatter(show_taint=show_taint)
            table.format(result.findings, result.taint_results)
            if result.enriched_findings:
                _print_enrichments(result.enriched_findings)
        case "json":
            click.echo(_json_output(result))
        case "markdown":
            markdown: Formatter = MarkdownFormatter()
            output = markdown.format(result.findings, result.taint_results)
            if result.enriched_findings:
                output += _markdown_enrichments(result.enriched_findings)
            click.echo(output)


def _json_output(result: ScanResult) -> str:
    """Serialise findings (and any enrichments) as a JSON string."""
    import json as json_lib  # noqa: PLC0415

    output = JsonFormatter().format(result.findings, result.taint_results)
    if not result.enriched_findings:
        return output
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
        for e in result.enriched_findings
    ]
    return json_lib.dumps(parsed, indent=2)


def _emit_graph(
    result: ScanResult, filtered: ScanResult, graph_file: str | None
) -> None:
    """Render the resource graph as Mermaid, to a file or stdout."""
    from cloudspill.output.graph import MermaidGraphFormatter  # noqa: PLC0415

    formatter = MermaidGraphFormatter()
    diagram = formatter.format(result.graph, filtered.findings, filtered.taint_results)
    summary = formatter.format_summary(
        result.graph, filtered.findings, filtered.taint_results
    )
    if graph_file:
        try:
            Path(graph_file).write_text(diagram, encoding="utf-8")
        except OSError as exc:
            raise click.ClickException(
                f"Could not write graph to {graph_file}: {exc}"
            ) from exc
        click.echo(f"Graph written to {graph_file}  ({summary})")
    else:
        click.echo("\n```mermaid")
        click.echo(diagram, nl=False)
        click.echo("```")
        click.echo(f"\n{summary}")


def _has_blocking_finding(findings: list[Finding], fail_on: str) -> bool:
    """True if any finding is at or above the --fail-on severity threshold."""
    order = list(Severity)
    threshold = order.index(Severity(fail_on))
    return any(order.index(f.severity) <= threshold for f in findings)


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


def _print_enrichments(enriched: list[EnrichedFinding]) -> None:
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


def _markdown_enrichments(enriched: list[EnrichedFinding]) -> str:
    lines = ["\n\n## AI Analysis\n"]
    for e in enriched:
        lines.append(f"### {e.finding.rule_id} — `{e.finding.resource}`\n")
        lines.append(e.explanation + "\n")
        lines.append(f"**Fix:**\n\n{e.remediation_patch}\n")
    return "\n".join(lines)


if __name__ == "__main__":
    scan()  # pylint: disable=no-value-for-parameter  # click injects options
