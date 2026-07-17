"""CLI entry point — nexum scan <file> / nexum report <file> / nexum validate <file>"""

from __future__ import annotations

import dataclasses
import enum
import json
from pathlib import Path

import typer

from .agent.triage import TriageUnavailable, generate_report
from .core import engine
from .core.baseline import BaselineError, filter_baseline, generate_baseline, load_baseline
from .core.formatters.sarif import to_sarif
from .core.ingestor import NexumIngestError, ingest
from .core.rules.base import Finding
from .core.scorer import ScoreResult, calculate
from .manifest.generator import generate
from .report.pdf_generator import generate_pdf
from .validator import ValidationResult, validate

app = typer.Typer(
    name="nexum",
    help="Nexum Scanner — analyse MCP/OpenAPI specs for AI safety risks.",
    add_completion=False,
)

_TIER_LABEL = {0: "Tier 0 — LOW RISK", 1: "Tier 1 — MODERATE RISK", 2: "Tier 2 — HIGH RISK"}
_TIER_COLOR = {0: typer.colors.GREEN, 1: typer.colors.YELLOW, 2: typer.colors.RED}


class ScanFormat(str, enum.Enum):
    json    = "json"
    summary = "summary"
    sarif   = "sarif"


_TABLE_WIDTH = 42
_SEVER_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _print_summary(
    file: Path,
    findings: list[Finding],
    result: ScoreResult,
    suppressed_count: int = 0,
    score_before: int | None = None,
) -> None:
    double = "═" * _TABLE_WIDTH
    single = "─" * _TABLE_WIDTH

    print(double)
    print(f" NEXUM SCAN — {file.name}")
    print(double)

    tier_label = _TIER_LABEL[result.tier].removeprefix("Tier ")
    score_line = f" Score     {result.score} / 100"
    if score_before is not None:
        score_line += f"  (was {score_before}/100 before baseline)"
    print(score_line)
    print(f" Tier      {tier_label}")

    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    parts = [f"{len(findings)} total"]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev in sev_counts:
            parts.append(f"{sev_counts[sev]} {sev}")
    print(f" Findings  {' · '.join(parts)}")
    if suppressed_count:
        print(f"           + {suppressed_count} suppressed via baseline")

    print(single)

    by_rule: dict[str, list[Finding]] = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f)

    for rule in engine._RULES:
        rule_id       = rule.RULE_ID    # type: ignore[attr-defined]
        rule_name     = rule.RULE_NAME  # type: ignore[attr-defined]
        rule_findings = by_rule.get(rule_id, [])
        count         = len(rule_findings)
        sev_label     = (
            min(rule_findings, key=lambda f: _SEVER_ORDER.get(f.severity, 99)).severity
            if count > 0 else "—"
        )
        print(f" {rule_id}  {rule_name:<20}  {count}  {sev_label}")

    print(double)
    print(" getnexum.dev")
    print(double)


@app.callback()
def _main() -> None:
    """Nexum Scanner — analyse MCP/OpenAPI specs for AI safety risks."""


@app.command()
def scan(
    file: Path = typer.Argument(..., help="MCP or OpenAPI spec file (JSON / YAML)"),
    fmt: ScanFormat = typer.Option(
        ScanFormat.json, "--format", help="Output format: json (default), summary or sarif",
    ),
    baseline_path: Path = typer.Option(
        None, "--baseline",
        help="Baseline file (.nexumbaseline.json) whose findings are suppressed before scoring",
    ),
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

    suppressed: list[Finding] = []
    score_before: int | None = None
    if baseline_path is not None:
        try:
            bl = load_baseline(baseline_path)
        except BaselineError as exc:
            typer.echo(f"Error: invalid baseline — {exc}", err=True)
            raise typer.Exit(code=1)
        score_before = calculate(findings).score
        findings, suppressed = filter_baseline(findings, bl)

    result = calculate(findings)
    manifest = generate(findings, result, str(file), spec)

    tier_text = _TIER_LABEL[result.tier]
    tier_color = _TIER_COLOR[result.tier]

    width = 48
    bar = "─" * width
    score_suffix = f"  (was {score_before}/100 before baseline)" if score_before is not None else ""
    score_line = f"  Nexum Risk Score : {result.score:>3} / 100{score_suffix}"
    tier_line  = f"  Risk Tier        : {tier_text}"
    src_line   = f"  Source           : {file.name}"
    typer.echo(bar,                                               err=True)
    typer.echo(typer.style(score_line, fg=tier_color, bold=True), err=True)
    typer.echo(typer.style(tier_line,  fg=tier_color, bold=True), err=True)
    typer.echo(src_line,                                          err=True)
    if suppressed:
        typer.echo(f"  Suppressed       : {len(suppressed)} via baseline", err=True)
    typer.echo(bar,                                               err=True)
    typer.echo("",                                                err=True)
    if fmt == ScanFormat.summary:
        _print_summary(file, findings, result, len(suppressed), score_before)
    elif fmt == ScanFormat.sarif:
        print(json.dumps(to_sarif(findings, str(file)), indent=2))
    else:
        print(json.dumps(manifest, indent=2))


def _print_validation_result(vresult: ValidationResult) -> None:
    assert len(vresult.flags) == len(vresult.findings_flagged), (
        f"flags/findings_flagged length mismatch: "
        f"{len(vresult.flags)} != {len(vresult.findings_flagged)}"
    )
    verdict_color = {
        "DISTRIBUTABLE":     typer.colors.GREEN,
        "REVIEW_REQUIRED":   typer.colors.YELLOW,
        "DO_NOT_DISTRIBUTE": typer.colors.RED,
    }.get(vresult.verdict, typer.colors.WHITE)
    passed = vresult.auto_checks_passed
    total  = vresult.auto_checks_total
    typer.echo(
        typer.style(
            f"Validation: {vresult.verdict} ({passed}/{total} checks passed)",
            fg=verdict_color, bold=True,
        ),
        err=True,
    )
    for flag, flagged in zip(vresult.flags, vresult.findings_flagged):
        if "finding" in flagged:
            f = flagged["finding"]
            detail = (
                f"finding {f.get('rule_id', '?')} {f.get('path', '?')} "
                f"— confidence {f.get('confidence', '?')}"
            )
        else:
            detail = f"field {flagged.get('field', '?')} — {flagged.get('reason', '')}"
        typer.echo(f"Flags: {flag} ({detail})", err=True)
    angles_str = ", ".join(vresult.manual_review_angles)
    typer.echo(f"Manual review required: angles {angles_str}", err=True)


@app.command()
def report(
    file: Path = typer.Argument(..., help="MCP or OpenAPI spec file (JSON / YAML)"),
    output: Path = typer.Option(Path("report.pdf"), "--output", "-o", help="Output PDF path"),
    exclude_path: list[str] = typer.Option(
        [], "--exclude-path", help="Exclude all findings at this exact path (repeatable)",
    ),
    run_validate: bool = typer.Option(
        False, "--validate", help="Run validator after PDF generation; exit code reflects verdict",
    ),
    triage: bool = typer.Option(
        False, "--triage",
        help="Add best-effort LLM triage prioritisation (calls the Anthropic API). "
             "Off by default — the deterministic report is unaffected either way.",
    ),
    baseline_path: Path = typer.Option(
        None, "--baseline",
        help="Baseline file (.nexumbaseline.json) whose findings are suppressed before scoring",
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

    if baseline_path is not None:
        try:
            bl = load_baseline(baseline_path)
        except BaselineError as exc:
            typer.echo(f"Error: invalid baseline — {exc}", err=True)
            raise typer.Exit(code=1)
        findings, suppressed = filter_baseline(findings, bl)
        if suppressed:
            typer.echo(f"Suppressed {len(suppressed)} finding(s) via baseline", err=True)

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

    # LLM triage is strictly additive and fail-closed: it never mutates the
    # deterministic manifest. With --triage off, generate_report makes no API
    # call and the report path is byte-identical to the deterministic-only flow.
    report_obj = generate_report(manifest, include_triage=triage)
    if isinstance(report_obj.triage_section, TriageUnavailable):
        typer.echo(report_obj.triage_section.reason, err=True)

    elapsed = generate_pdf(
        findings, result, manifest, str(file), output,
        excluded_paths=sorted(excluded),
        triage_section=report_obj.triage_section,
    )

    tier_text  = _TIER_LABEL[result.tier]
    tier_color = _TIER_COLOR[result.tier]

    typer.echo(typer.style(f"PDF generated: {output}", fg=typer.colors.GREEN, bold=True))
    typer.echo(f"  Score   : {result.score} / 100")
    typer.echo(typer.style(f"  Tier    : {tier_text}", fg=tier_color, bold=True))
    typer.echo(f"  Findings: {len(findings)}")
    typer.echo(f"  Time    : {elapsed:.2f}s")
    typer.echo(f"  Size    : {output.stat().st_size // 1024} KB")

    if run_validate:
        vresult = validate(manifest)
        _print_validation_result(vresult)
        if vresult.verdict == "DO_NOT_DISTRIBUTE":
            raise typer.Exit(code=1)
        if vresult.verdict == "REVIEW_REQUIRED":
            raise typer.Exit(code=2)


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


@app.command()
def baseline(
    file: Path = typer.Argument(..., help="MCP or OpenAPI spec file (JSON / YAML)"),
    output: Path = typer.Option(
        Path(".nexumbaseline.json"), "--output", "-o", help="Baseline file to write",
    ),
) -> None:
    """Scan a spec and write a baseline accepting every current finding for review."""
    if not file.exists():
        typer.echo(f"Error: file not found — '{file}'", err=True)
        raise typer.Exit(code=1)

    try:
        spec = ingest(file)
    except NexumIngestError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)

    findings = engine.run(spec)
    generate_baseline(findings, output)

    typer.echo(
        typer.style(f"Baseline written: {output}", fg=typer.colors.GREEN, bold=True),
    )
    typer.echo(f"  {len(findings)} finding(s) accepted — review and edit 'reason' fields before use.")


if __name__ == "__main__":
    app()
