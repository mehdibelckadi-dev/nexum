"""CLI entry point — pact scan <file>"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from .core import engine
from .core.ingestor import PactIngestError, ingest
from .core.scorer import calculate
from .manifest.generator import generate

app = typer.Typer(
    name="pact",
    help="PACT Scanner — analyse MCP/OpenAPI specs for AI safety risks.",
    add_completion=False,
)

_TIER_LABEL = {0: "Tier 0 — LOW RISK", 1: "Tier 1 — MODERATE RISK", 2: "Tier 2 — HIGH RISK"}
_TIER_COLOR = {0: typer.colors.GREEN, 1: typer.colors.YELLOW, 2: typer.colors.RED}


@app.callback()
def _main() -> None:
    """PACT Scanner — analyse MCP/OpenAPI specs for AI safety risks."""


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
    except PactIngestError as exc:
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
    score_line = f"  PACT Risk Score : {result.score:>3} / 100"
    tier_line  = f"  Risk Tier       : {tier_text}"
    src_line   = f"  Source          : {file.name}"
    typer.echo(typer.style(score_line, fg=tier_color, bold=True))
    typer.echo(typer.style(tier_line,  fg=tier_color, bold=True))
    typer.echo(src_line)
    typer.echo(bar)
    typer.echo()
    typer.echo(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    app()
