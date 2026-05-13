"""CLI entry point — nexum scan <file> / nexum report <file> / nexum validate <file>"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import typer

from .core import engine
from .core.ingestor import NexumIngestError, ingest
from .core.scorer import calculate
from .manifest.generator import generate
from .report.pdf_generator import generate_pdf
from .validator import validate

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
    score_line = f"  Nexum Risk Score : {result.score:>3} / 100"
    tier_line  = f"  Risk Tier        : {tier_text}"
    src_line   = f"  Source           : {file.name}"
    typer.echo(bar,                                               err=True)
    typer.echo(typer.style(score_line, fg=tier_color, bold=True), err=True)
    typer.echo(typer.style(tier_line,  fg=tier_color, bold=True), err=True)
    typer.echo(src_line,                                          err=True)
    typer.echo(bar,                                               err=True)
    typer.echo("",                                                err=True)
    print(json.dumps(manifest, indent=2))


@app.command()
def report(
    file: Path = typer.Argument(..., help="MCP or OpenAPI spec file (JSON / YAML)"),
    output: Path = typer.Option(Path("report.pdf"), "--output", "-o", help="Output PDF path"),
    exclude_path: list[str] = typer.Option(
        [], "--exclude-path", help="Exclude all findings at this exact path (repeatable)",
    ),
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

    excluded: set[str] = set(exclude_path)
    if excluded:
        before   = len(findings)
        findings = [f for f in findings if f.path not in excluded]
        typer.echo(
            f"Excluded {before - len(findings)} finding(s) via --exclude-path: "
            f"{', '.join(sorted(excluded))}",
            err=True,
        )

    result   = calculate(findings)
    manifest = generate(findings, result, str(file), spec)

    elapsed = generate_pdf(
        findings, result, manifest, str(file), output,
        excluded_paths=sorted(excluded),
    )

    tier_text  = _TIER_LABEL[result.tier]
    tier_color = _TIER_COLOR[result.tier]

    typer.echo(typer.style(f"PDF generated: {output}", fg=typer.colors.GREEN, bold=True))
    typer.echo(f"  Score   : {result.score} / 100")
    typer.echo(typer.style(f"  Tier    : {tier_text}", fg=tier_color, bold=True))
    typer.echo(f"  Findings: {len(findings)}")
    typer.echo(f"  Time    : {elapsed:.2f}s")
    typer.echo(f"  Size    : {output.stat().st_size // 1024} KB")


@app.command()
def validate_manifest(
    findings_json: Path = typer.Argument(
        ..., help="JSON file produced by `nexum scan` (Trust Manifest draft)"
    ),
    strict: bool = typer.Option(
        False, "--strict", help="Treat REVIEW_REQUIRED as exit code 1 (useful in CI)"
    ),
) -> None:
    """Validate a Trust Manifest draft and emit a ValidationResult as JSON."""
    if not findings_json.exists():
        typer.echo(f"Error: file not found — '{findings_json}'", err=True)
        raise typer.Exit(code=1)

    try:
        manifest = json.loads(findings_json.read_text())
    except json.JSONDecodeError as exc:
        typer.echo(f"Error: invalid JSON — {exc}", err=True)
        raise typer.Exit(code=1)

    result = validate(manifest)
    print(json.dumps(dataclasses.asdict(result), indent=2))

    if result.verdict == "DO_NOT_DISTRIBUTE":
        raise typer.Exit(code=1)
    if result.verdict == "REVIEW_REQUIRED":
        raise typer.Exit(code=1 if strict else 2)


if __name__ == "__main__":
    app()
