"""PDF report generator for Nexum scan results."""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ..core.rules.base import Finding
from ..core.scorer import ScoreResult

# ---------------------------------------------------------------------------
# Severity palette — hex strings for markup, Color objects for TableStyle
# ---------------------------------------------------------------------------

_SEVERITY_HEX: dict[str, str] = {
    "CRITICAL": "#CC0000",
    "HIGH":     "#E65C00",
    "MEDIUM":   "#B8860B",
    "LOW":      "#2E7D32",
}
_SEVERITY_COLOR: dict[str, colors.Color] = {
    k: colors.HexColor(v) for k, v in _SEVERITY_HEX.items()
}

_TIER_LABEL: dict[int, str] = {
    0: "Tier 0 — LOW RISK",
    1: "Tier 1 — MODERATE RISK",
    2: "Tier 2 — HIGH RISK",
}
_TIER_HEX: dict[int, str] = {0: "#2E7D32", 1: "#B8860B", 2: "#CC0000"}
_TIER_COLOR: dict[int, colors.Color] = {k: colors.HexColor(v) for k, v in _TIER_HEX.items()}

_SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

_PAGE_W, _PAGE_H = A4
_MARGIN   = 2.0 * cm
_INNER_W  = _PAGE_W - 2 * _MARGIN


# ---------------------------------------------------------------------------
# Style sheet
# ---------------------------------------------------------------------------

def _build_styles() -> dict[str, ParagraphStyle]:
    base   = getSampleStyleSheet()["Normal"]
    styles: dict[str, ParagraphStyle] = {}

    def _s(name: str, **kw) -> ParagraphStyle:
        p = ParagraphStyle(name, parent=base, **kw)
        styles[name] = p
        return p

    _s("logo",         fontName="Helvetica-Bold",    fontSize=28, textColor=colors.HexColor("#1A1A2E"), leading=34)
    _s("report_title", fontName="Helvetica",          fontSize=13, textColor=colors.HexColor("#444444"), leading=18)
    _s("date_line",    fontName="Helvetica",          fontSize=9,  textColor=colors.HexColor("#888888"), leading=13)
    _s("score_num",    fontName="Helvetica-Bold",     fontSize=72, textColor=colors.black,               leading=80)
    _s("score_denom",  fontName="Helvetica",          fontSize=28, textColor=colors.HexColor("#666666"), leading=36)
    _s("tier_label",   fontName="Helvetica-Bold",     fontSize=14, leading=18)
    _s("magnitude",    fontName="Helvetica",          fontSize=10, textColor=colors.HexColor("#333333"), leading=14)
    _s("section_hdr",  fontName="Helvetica-Bold",     fontSize=12, textColor=colors.HexColor("#1A1A2E"), leading=16, spaceBefore=6)
    _s("rule_hdr",     fontName="Helvetica-Bold",     fontSize=10, leading=14, spaceBefore=4)
    _s("finding_id",   fontName="Helvetica-Bold",     fontSize=10, leading=14)
    _s("finding_path", fontName="Helvetica",          fontSize=9,  textColor=colors.HexColor("#555555"), leading=12)
    _s("finding_exp",  fontName="Helvetica",          fontSize=8,  textColor=colors.HexColor("#333333"), leading=11)
    _s("guardrail",    fontName="Helvetica-Oblique",  fontSize=8,  textColor=colors.HexColor("#555555"), leading=11)
    _s("body",         fontName="Helvetica",          fontSize=9,  textColor=colors.HexColor("#333333"), leading=12)
    _s("no_issues",    fontName="Helvetica-Bold",     fontSize=16, textColor=colors.HexColor("#2E7D32"), leading=20)
    _s("tbl_cell",     fontName="Helvetica",          fontSize=8,  textColor=colors.HexColor("#333333"), leading=10)
    return styles


# ---------------------------------------------------------------------------
# Top-findings selection (page 1)
# ---------------------------------------------------------------------------

def _select_top(findings: list[Finding]) -> list[Finding]:
    """Return up to 3 representative findings for the summary section."""
    if not findings:
        return []

    by_rule: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_rule[f.rule_id].append(f)

    if len(by_rule) == 1:
        rule_findings = list(by_rule.values())[0]
        return sorted(rule_findings, key=lambda f: len(f.path), reverse=True)[:3]

    # Multiple rules: one representative per rule, worst severity first
    sorted_buckets = sorted(
        by_rule.values(),
        key=lambda fs: _SEVERITY_ORDER.get(fs[0].severity, 99),
    )
    top: list[Finding] = []
    for bucket in sorted_buckets:
        top.append(bucket[0])
        if len(top) == 3:
            break
    return top


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def truncate_path(path: str, max_chars: int = 80) -> str:
    """Center-truncate a path so the tail (most specific segment) is preserved."""
    if len(path) <= max_chars:
        return path
    keep = max_chars - 3  # reserve 3 chars for "..."
    head = keep // 2
    tail = keep - head
    return path[:head] + "..." + path[-tail:]


# ---------------------------------------------------------------------------
# Page 1
# ---------------------------------------------------------------------------

def _page1(
    findings: list[Finding],
    result: ScoreResult,
    source_name: str,
    styles: dict[str, ParagraphStyle],
) -> list:
    els: list = []

    scan_ts = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    els.append(Paragraph("NEXUM", styles["logo"]))
    els.append(Paragraph("Security Scan Report", styles["report_title"]))
    els.append(Paragraph(
        f"Generated: {scan_ts} &nbsp;&nbsp;·&nbsp;&nbsp; Source: {source_name}",
        styles["date_line"],
    ))
    els.append(Spacer(1, 0.45 * cm))
    els.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CCCCCC")))
    els.append(Spacer(1, 0.35 * cm))

    if not findings:
        els.append(Spacer(1, 1.5 * cm))
        els.append(Paragraph("No issues detected", styles["no_issues"]))
        return els

    # Score block: score number + "/ 100" side by side
    score_tbl = Table(
        [[Paragraph(str(result.score), styles["score_num"]),
          Paragraph("/ 100", styles["score_denom"])]],
        colWidths=[4.5 * cm, 3 * cm],
    )
    score_tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "BOTTOM"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 0),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    els.append(score_tbl)
    els.append(Spacer(1, 0.12 * cm))

    tier_color = _TIER_COLOR[result.tier]
    tier_style = ParagraphStyle("tier_c", parent=styles["tier_label"], textColor=tier_color)
    els.append(Paragraph(_TIER_LABEL[result.tier], tier_style))
    els.append(Spacer(1, 0.28 * cm))

    # Magnitude line
    counts: Counter[str] = Counter(f.severity for f in findings)
    sev_parts = "  ·  ".join(
        f'<font color="{_SEVERITY_HEX[sev]}">{counts[sev]} {sev}</font>'
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        if counts[sev]
    )
    els.append(Paragraph(
        f"<b>{len(findings)}</b> findings total &nbsp;&nbsp;·&nbsp;&nbsp; {sev_parts}",
        styles["magnitude"],
    ))
    els.append(Spacer(1, 0.35 * cm))
    els.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CCCCCC")))
    els.append(Spacer(1, 0.25 * cm))

    # Top findings
    els.append(Paragraph("Top Findings", styles["section_hdr"]))
    els.append(Spacer(1, 0.18 * cm))

    for f in _select_top(findings):
        hex_c  = _SEVERITY_HEX.get(f.severity, "#333333")
        id_sty = ParagraphStyle(f"fid_{f.rule_id}", parent=styles["finding_id"], textColor=colors.HexColor(hex_c))
        els.append(Paragraph(
            f'[{f.rule_id}] &nbsp;<font color="{hex_c}">{f.severity}</font>',
            id_sty,
        ))
        els.append(Paragraph(truncate_path(f.path), styles["finding_path"]))
        els.append(Paragraph(f.human_explanation, styles["finding_exp"]))
        els.append(Spacer(1, 0.22 * cm))

    # Rule summary table — only when more than one rule fired
    by_rule_summary: dict[str, dict] = {}
    for f in findings:
        if f.rule_id not in by_rule_summary:
            by_rule_summary[f.rule_id] = {"rule_name": f.rule_name, "severity": f.severity, "count": 0}
        by_rule_summary[f.rule_id]["count"] += 1

    if len(by_rule_summary) > 1:
        els.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CCCCCC")))
        els.append(Spacer(1, 0.2 * cm))
        els.append(Paragraph("Findings by Rule", styles["section_hdr"]))
        els.append(Spacer(1, 0.15 * cm))

        sorted_rules = sorted(
            by_rule_summary.items(),
            key=lambda kv: _SEVERITY_ORDER.get(kv[1]["severity"], 99),
        )

        data = [[
            Paragraph("<b>Rule ID</b>",   styles["tbl_cell"]),
            Paragraph("<b>Rule Name</b>", styles["tbl_cell"]),
            Paragraph("<b>Findings</b>",  styles["tbl_cell"]),
            Paragraph("<b>Severity</b>",  styles["tbl_cell"]),
        ]]
        for rule_id, info in sorted_rules:
            hex_c = _SEVERITY_HEX.get(info["severity"], "#333333")
            data.append([
                Paragraph(rule_id, styles["tbl_cell"]),
                Paragraph(info["rule_name"], styles["tbl_cell"]),
                Paragraph(str(info["count"]), styles["tbl_cell"]),
                Paragraph(f'<font color="{hex_c}">{info["severity"]}</font>', styles["tbl_cell"]),
            ])

        summary_tbl = Table(data, colWidths=[2.0 * cm, 5.5 * cm, 1.8 * cm, 2.5 * cm])
        tbl_style = [
            ("BACKGROUND",    (0, 0), (-1, 0),  colors.HexColor("#F0F0F0")),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("GRID",          (0, 0), (-1, -1), 0.25, colors.HexColor("#DDDDDD")),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN",         (2, 0), (2, -1),  "RIGHT"),
            ("LEFTPADDING",   (0, 0), (-1, -1), 4),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for i in range(1, len(data)):
            if i % 2 == 0:
                tbl_style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FAFAFA")))
        summary_tbl.setStyle(TableStyle(tbl_style))
        els.append(summary_tbl)

    return els


# ---------------------------------------------------------------------------
# Page 2
# ---------------------------------------------------------------------------

def _page2(
    findings: list[Finding],
    manifest: dict[str, Any],
    styles: dict[str, ParagraphStyle],
) -> list:
    els: list = []
    if not findings:
        return els

    els.append(Paragraph("Full Findings — Grouped by Rule", styles["section_hdr"]))
    els.append(Spacer(1, 0.2 * cm))

    # Group preserving engine sort order
    by_rule: dict[str, list[Finding]] = defaultdict(list)
    rule_order: list[str] = []
    for f in findings:
        if f.rule_id not in by_rule:
            rule_order.append(f.rule_id)
        by_rule[f.rule_id].append(f)

    for rule_id in rule_order:
        bucket = by_rule[rule_id]
        first  = bucket[0]
        sev_c  = _SEVERITY_COLOR.get(first.severity, colors.black)
        hex_c  = _SEVERITY_HEX.get(first.severity, "#333333")

        rule_sty = ParagraphStyle(f"rh_{rule_id}", parent=styles["rule_hdr"], textColor=sev_c)
        els.append(Paragraph(
            f'{rule_id} — {first.rule_name} &nbsp;<font color="{hex_c}">({first.severity})</font>',
            rule_sty,
        ))
        els.append(Spacer(1, 0.1 * cm))

        shown     = bucket[:5]
        remainder = len(bucket) - 5

        header_row = [
            Paragraph("<b>Path</b>", styles["tbl_cell"]),
            Paragraph("<b>Method</b>", styles["tbl_cell"]),
            Paragraph("<b>Severity</b>", styles["tbl_cell"]),
        ]
        data = [header_row]
        for f in shown:
            sev_hex = _SEVERITY_HEX.get(f.severity, "#333333")
            data.append([
                Paragraph(truncate_path(f.path), styles["tbl_cell"]),
                Paragraph(f.method, styles["tbl_cell"]),
                Paragraph(f'<font color="{sev_hex}">{f.severity}</font>', styles["tbl_cell"]),
            ])
        if remainder > 0:
            data.append([
                Paragraph(f"<i>...and {remainder} more</i>", styles["tbl_cell"]),
                Paragraph("", styles["tbl_cell"]),
                Paragraph("", styles["tbl_cell"]),
            ])

        col_w = [_INNER_W * 0.71, _INNER_W * 0.12, _INNER_W * 0.17]
        tbl   = Table(data, colWidths=col_w, repeatRows=1)

        tbl_style = [
            ("BACKGROUND",   (0, 0), (-1, 0),  colors.HexColor("#F0F0F0")),
            ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, -1), 8),
            ("GRID",         (0, 0), (-1, -1), 0.25, colors.HexColor("#DDDDDD")),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING",  (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING",   (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 3),
        ]
        # Alternating row backgrounds
        for i in range(1, len(data)):
            if i % 2 == 0:
                tbl_style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FAFAFA")))

        tbl.setStyle(TableStyle(tbl_style))
        els.append(tbl)
        els.append(Spacer(1, 0.12 * cm))
        els.append(Paragraph(
            f"<b>Guardrail:</b> {first.guardrail_suggestion}",
            styles["guardrail"],
        ))
        els.append(Spacer(1, 0.35 * cm))

    # Manual Review Required
    manual = manifest.get("manual_review_required", [])
    if manual:
        els.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CCCCCC")))
        els.append(Spacer(1, 0.18 * cm))
        els.append(Paragraph("Manual Review Required", styles["section_hdr"]))
        els.append(Spacer(1, 0.1 * cm))
        for item in manual:
            els.append(Paragraph(
                f"• <b>{item['field']}</b>: {item['reason']}",
                styles["body"],
            ))
            els.append(Spacer(1, 0.1 * cm))

    return els


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_pdf(
    findings: list[Finding],
    result: ScoreResult,
    manifest: dict[str, Any],
    source_file: str,
    output_path: Path,
) -> float:
    """Render the 2-page PDF report. Returns elapsed wall-clock seconds."""
    t0 = time.perf_counter()

    styles = _build_styles()
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=_MARGIN,
        rightMargin=_MARGIN,
        topMargin=_MARGIN,
        bottomMargin=_MARGIN,
        title="Nexum Security Scan Report",
        author="Nexum Scanner",
    )

    story = (
        _page1(findings, result, Path(source_file).name, styles)
        + [PageBreak()]
        + _page2(findings, manifest, styles)
    )
    doc.build(story)
    return time.perf_counter() - t0
