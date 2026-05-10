"""CLI entry point — nexum scan <file> / nexum report <file>"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from .core import engine
from .core.ingestor import NexumIngestError, ingest
from .core.scorer import calculate
from .manifest.generator import generate
from .report.pdf_generator import generate_pdf

app = typer.Typer(
    name="nexum",
    help="Nexum Scanner — analyse MCP/OpenAPI specs for AI safety risks.",
    add_completion=False,
)

_TIER_LABEL = {0: "Tier 0 — LOW RISK", 1: "Tier 1 — MODERATE RISK", 2: "Tier 2 — HIGH RISK"}
_TIER_COLOR = {0: typer.colors.GREEN, 1: typer.colors.YELLOW, 2: typer.colors.RED}


@app.callback()
def _main() -> None:
    """Nexum Scanner — analyse MCP/OpenAPI specs for AI safety risks."""


@app.command()
def scan(
    file: Path = typer.Argument(..., help="MCP or OpenAPI spec file (JSON / YAML)"),
) -> None:
    """Scan a spec file and print the Trust Manifest draft and Risk Score."""
    if not file.exists():
        typer.echo(f"Error: file not found — '{file}'", err=True)
        raise typer.Exit(code=1)

    try:
        spec = ingest(file)
    except NexumIngestError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)

    findings = engine.run(spec)
    result = calculate(findings)
    manifest = generate(findings, result, str(file), spec)

    tier_text = _TIER_LABEL[result.tier]
    tier_color = _TIER_COLOR[result.tier]

    width = 48
    bar = "─" * width
    typer.echo(bar)
    score_line = f"  Nexum Risk Score : {result.score:>3} / 100"
    tier_line  = f"  Risk Tier        : {tier_text}"
    src_line   = f"  Source           : {file.name}"
    typer.echo(typer.style(score_line, fg=tier_color, bold=True))
    typer.echo(typer.style(tier_line,  fg=tier_color, bold=True))
    typer.echo(src_line)
    typer.echo(bar)
    typer.echo()
    typer.echo(json.dumps(manifest, indent=2))


@app.command()
def report(
    file: Path = typer.Argument(..., help="MCP or OpenAPI spec file (JSON / YAML)"),
    output: Path = typer.Option(Path("report.pdf"), "--output", "-o", help="Output PDF path"),
) -> None:
    """Generate a PDF Security Report for a spec file."""
    if not file.exists():
        typer.echo(f"Error: file not found — '{file}'", err=True)
        raise typer.Exit(code=1)

    try:
        spec = ingest(file)
    except NexumIngestError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)

    findings = engine.run(spec)
    result   = calculate(findings)
    manifest = generate(findings, result, str(file), spec)

    elapsed = generate_pdf(findings, result, manifest, str(file), output)

    tier_text  = _TIER_LABEL[result.tier]
    tier_color = _TIER_COLOR[result.tier]

    typer.echo(typer.style(f"PDF generated: {output}", fg=typer.colors.GREEN, bold=True))
    typer.echo(f"  Score   : {result.score} / 100")
    typer.echo(typer.style(f"  Tier    : {tier_text}", fg=tier_color, bold=True))
    typer.echo(f"  Findings: {len(findings)}")
    typer.echo(f"  Time    : {elapsed:.2f}s")
    typer.echo(f"  Size    : {output.stat().st_size // 1024} KB")


if __name__ == "__main__":
    app()
