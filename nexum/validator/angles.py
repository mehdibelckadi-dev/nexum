"""Deterministic validation angles for Nexum manifests."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..core.scorer import _SEVERITY_POINTS
from .known_fps import match_false_positive

# ---------------------------------------------------------------------------
# Angle 0 — Integrity
# ---------------------------------------------------------------------------

def check_integrity(manifest: dict[str, Any]) -> tuple[list[str], list[dict]]:
    """Verify structural integrity of a manifest dict.

    Checks: manifest_version present, scanned_at is valid ISO 8601,
    nexum_risk_score matches the sum of findings, source_file present.
    """
    flags: list[str] = []
    flagged: list[dict] = []

    if not manifest.get("manifest_version"):
        flags.append("MISSING_FIELD")
        flagged.append({"field": "manifest_version", "reason": "Field is absent or empty"})

    if not manifest.get("source_file"):
        flags.append("MISSING_FIELD")
        flagged.append({"field": "source_file", "reason": "Field is absent or empty"})

    scanned_at = manifest.get("scanned_at")
    if not scanned_at:
        flags.append("MISSING_FIELD")
        flagged.append({"field": "scanned_at", "reason": "Field is absent or empty"})
    else:
        try:
            datetime.fromisoformat(str(scanned_at))
        except ValueError:
            flags.append("MISSING_FIELD")
            flagged.append({
                "field": "scanned_at",
                "reason": f"Not a valid ISO 8601 timestamp: {scanned_at!r}",
            })

    reported_score = manifest.get("nexum_risk_score")
    if reported_score is not None:
        findings_summary = manifest.get("findings_summary", [])
        raw_sum = sum(
            _SEVERITY_POINTS.get(f.get("severity", ""), 0)
            for f in findings_summary
            if isinstance(f, dict)
        )
        expected = min(100, raw_sum)
        if reported_score != expected:
            flags.append("SCORE_MISMATCH")
            flagged.append({
                "field": "nexum_risk_score",
                "reason": (
                    f"Reported score {reported_score} does not match "
                    f"computed score {expected} from findings_summary"
                ),
            })

    return flags, flagged


# ---------------------------------------------------------------------------
# Angle 4 — Known false positives
# ---------------------------------------------------------------------------

def check_false_positives(findings: list[dict[str, Any]]) -> tuple[list[str], list[dict]]:
    """Cross-reference each finding against the known false-positive database."""
    flags: list[str] = []
    flagged: list[dict] = []

    for f in findings:
        matched, incomplete = match_false_positive(f)
        if incomplete:
            flags.append("INCOMPLETE_DATA")
            flagged.append({
                "finding": f,
                "reason": (
                    "Required match_field absent in reconstructed finding — "
                    "cannot evaluate false-positive rule"
                ),
            })
        elif matched:
            flags.append("LIKELY_FALSE_POSITIVE")
            flagged.append({
                "finding": f,
                "reason": matched["description"],
            })

    return flags, flagged


# ---------------------------------------------------------------------------
# Angle 7 — Severity / confidence criteria
# ---------------------------------------------------------------------------

def check_severity_confidence(findings: list[dict[str, Any]]) -> tuple[list[str], list[dict]]:
    """Flag findings whose severity/confidence combination warrants review."""
    flags: list[str] = []
    flagged: list[dict] = []

    for f in findings:
        severity = f.get("severity", "")
        confidence = f.get("confidence", "HIGH")

        if confidence == "LOW":
            flags.append("LIKELY_FALSE_POSITIVE")
            flagged.append({
                "finding": f,
                "reason": "confidence == LOW — finding reliability is insufficient for distribution",
            })
        elif severity == "CRITICAL" and confidence == "MEDIUM":
            flags.append("REVIEW_REQUIRED")
            flagged.append({
                "finding": f,
                "reason": "CRITICAL severity with MEDIUM confidence requires human verification",
            })

    return flags, flagged


# ---------------------------------------------------------------------------
# Angle 8 — Document completeness
# ---------------------------------------------------------------------------

def check_completeness(manifest: dict[str, Any]) -> tuple[list[str], list[dict]]:
    """Verify that all required manifest sections exist and are internally consistent."""
    flags: list[str] = []
    flagged: list[dict] = []

    score = manifest.get("nexum_risk_score", 0)
    findings_summary = manifest.get("findings_summary")
    if score > 0 and (findings_summary is None or len(findings_summary) == 0):
        flags.append("MISSING_FIELD")
        flagged.append({
            "field": "findings_summary",
            "reason": f"nexum_risk_score is {score} but findings_summary is empty or absent",
        })

    if "manual_review_required" not in manifest:
        flags.append("MISSING_FIELD")
        flagged.append({
            "field": "manual_review_required",
            "reason": "Field is absent from manifest",
        })

    invariants = manifest.get("auto_detected_invariants")
    if not isinstance(invariants, dict):
        flags.append("MISSING_FIELD")
        flagged.append({
            "field": "auto_detected_invariants",
            "reason": "Field is absent or not an object",
        })
    else:
        for sub in ("immutable_fields", "numeric_limits", "required_headers"):
            if sub not in invariants:
                flags.append("MISSING_FIELD")
                flagged.append({
                    "field": f"auto_detected_invariants.{sub}",
                    "reason": "Sub-field is absent",
                })

    return flags, flagged
