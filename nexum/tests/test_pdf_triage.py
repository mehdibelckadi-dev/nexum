"""Tests for the advisory LLM triage section in the PDF report.

These verify that the default report path is unaffected (triage_section=None
renders nothing) and that the two triage states render correctly without ever
leaking the internal failure category.
"""

from pathlib import Path

from nexum.agent.triage import TriageFailureCategory, TriageItem, TriageUnavailable
from nexum.core.rules.base import Finding
from nexum.core.scorer import calculate
from nexum.report.pdf_generator import (
    _build_styles,
    _triage_elements,
    generate_pdf,
)

_STYLES = _build_styles()


def _text(elements) -> str:
    """Concatenate the text of every Paragraph flowable (Spacers/HRs have none)."""
    return " ".join(getattr(e, "text", "") or "" for e in elements)


class TestTriageElements:
    def test_default_path_renders_nothing(self):
        # triage_section=None is exactly what `nexum report` (no --triage)
        # passes: the story gains an empty list, so the PDF is unchanged.
        assert _triage_elements(None, _STYLES) == []

    def test_items_render_with_finding_ids(self):
        items = [
            TriageItem("NEXUM-002@/v1/charges", "Fix first — chargeback risk.", "Add Idempotency-Key."),
            TriageItem("NEXUM-004@/v1/widgets", "Lower priority.", "Add Idempotency-Key."),
        ]
        els = _triage_elements(items, _STYLES)
        assert els  # non-empty
        text = _text(els)
        assert "NEXUM-002@/v1/charges" in text
        assert "NEXUM-004@/v1/widgets" in text
        assert "Priority:" in text
        assert "Remediation:" in text

    def test_unavailable_renders_reason_never_category(self):
        unavailable = TriageUnavailable(
            reason="Triage prioritization unavailable for this report. "
                   "Deterministic findings and risk score are unaffected.",
            category=TriageFailureCategory.INTEGRITY,
        )
        text = _text(_triage_elements(unavailable, _STYLES)).lower()
        assert "unavailable" in text
        # The internal category must never reach the rendered PDF.
        assert "integrity" not in text
        assert "operational" not in text


class TestGeneratePdfWithTriage:
    def _fixture(self):
        findings = [Finding(
            rule_id="NEXUM-002", rule_name="DestructiveAmbiguity", severity="CRITICAL",
            path="/v1/charges", method="DELETE", evidence_snippet="{}",
            human_explanation="x", guardrail_suggestion="y",
        )]
        result = calculate(findings)
        manifest = {"manual_review_required": []}
        return findings, result, manifest

    def test_default_pdf_generates_without_triage(self, tmp_path):
        findings, result, manifest = self._fixture()
        out = tmp_path / "default.pdf"
        # No triage_section arg — the default report path.
        elapsed = generate_pdf(findings, result, manifest, "spec.yaml", out)
        assert out.exists() and out.stat().st_size > 0
        assert elapsed >= 0

    def test_pdf_with_triage_items_generates(self, tmp_path):
        findings, result, manifest = self._fixture()
        items = [TriageItem("NEXUM-002@/v1/charges", "Fix first.", "Add Idempotency-Key.")]
        out = tmp_path / "triage.pdf"
        generate_pdf(findings, result, manifest, "spec.yaml", out, triage_section=items)
        assert out.exists() and out.stat().st_size > 0
