"""ValidationResult dataclass and the top-level validate() function."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .angles import (
    check_completeness,
    check_false_positives,
    check_integrity,
    check_severity_confidence,
)

# Angles that always require a human — never automatable.
_MANUAL_REVIEW_ANGLES = ["1", "2", "3", "5", "6"]


@dataclass
class ValidationResult:
    auto_checks_passed: int
    auto_checks_total: int
    flags: list[str] = field(default_factory=list)
    findings_flagged: list[dict] = field(default_factory=list)
    manual_review_angles: list[str] = field(default_factory=list)
    verdict: str = "DISTRIBUTABLE"


def validate(
    manifest: dict[str, Any],
    findings: list[dict[str, Any]] | None = None,
) -> ValidationResult:
    """Validate a Trust Manifest dict produced by nexum scan.

    If findings is None the findings_summary list inside the manifest is used.
    Note: reconstructed findings lack evidence_snippet, which may trigger
    INCOMPLETE_DATA flags in Angle 4.
    """
    if findings is None:
        findings = [
            f for f in manifest.get("findings_summary", [])
            if isinstance(f, dict)
        ]

    # Run all four automated angles.
    angle_results: list[tuple[list[str], list[dict]]] = [
        check_integrity(manifest),        # Angle 0
        check_false_positives(findings),   # Angle 4
        check_severity_confidence(findings),  # Angle 7
        check_completeness(manifest),      # Angle 8
    ]

    all_flags: list[str] = []
    all_flagged: list[dict] = []
    checks_passed = 0

    for flags, flagged in angle_results:
        if not flags:
            checks_passed += 1
        all_flags.extend(flags)
        all_flagged.extend(flagged)

    verdict = _compute_verdict(all_flags, findings)

    return ValidationResult(
        auto_checks_passed=checks_passed,
        auto_checks_total=len(angle_results),
        flags=all_flags,
        findings_flagged=all_flagged,
        manual_review_angles=_MANUAL_REVIEW_ANGLES,
        verdict=verdict,
    )


def _compute_verdict(flags: list[str], findings: list[dict[str, Any]]) -> str:
    # Priority 1: DO_NOT_DISTRIBUTE
    has_low_confidence = any(
        f.get("confidence") == "LOW" for f in findings if isinstance(f, dict)
    )
    if has_low_confidence or "SCORE_MISMATCH" in flags:
        return "DO_NOT_DISTRIBUTE"

    # Priority 2: REVIEW_REQUIRED — any CRITICAL with MEDIUM confidence
    has_critical_medium = any(
        f.get("severity") == "CRITICAL" and f.get("confidence") == "MEDIUM"
        for f in findings
        if isinstance(f, dict)
    )
    if has_critical_medium or "REVIEW_REQUIRED" in flags:
        return "REVIEW_REQUIRED"

    return "DISTRIBUTABLE"
