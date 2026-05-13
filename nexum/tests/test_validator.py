"""Tests for nexum/validator/ — angles, verdict rules, and CLI command."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from nexum.validator import ValidationResult, validate
from nexum.validator.known_fps import match_false_positive


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _base_manifest(**overrides: Any) -> dict[str, Any]:
    """Return a minimal valid manifest; apply overrides on top."""
    manifest: dict[str, Any] = {
        "manifest_version": "1.0-draft",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "source_file": "sample.yaml",
        "nexum_risk_score": 0,
        "inferred_risk_tier": 0,
        "model_compatibility_range": "REQUIRES_HUMAN_REVIEW",
        "auto_detected_invariants": {
            "immutable_fields": [],
            "numeric_limits": {},
            "required_headers": [],
        },
        "findings_summary": [],
        "manual_review_required": [],
    }
    manifest.update(overrides)
    return manifest


def _finding_dict(
    rule_id: str = "NEXUM-001",
    rule_name: str = "AuthLeakageRisk",
    severity: str = "HIGH",
    path: str = "/api/resource",
    method: str = "GET",
    confidence: str = "HIGH",
    confidence_reason: str = "",
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "path": path,
        "method": method,
        "confidence": confidence,
        "confidence_reason": confidence_reason,
    }


# ---------------------------------------------------------------------------
# test_clean_manifest_is_distributable
# ---------------------------------------------------------------------------

class TestCleanManifest:
    def test_clean_manifest_is_distributable(self):
        result = validate(_base_manifest())
        assert isinstance(result, ValidationResult)
        assert result.verdict == "DISTRIBUTABLE"
        assert result.flags == []
        assert result.findings_flagged == []
        assert result.auto_checks_passed == result.auto_checks_total

    def test_manual_review_angles_always_present(self):
        result = validate(_base_manifest())
        assert result.manual_review_angles == ["1", "2", "3", "5", "6"]

    def test_auto_checks_total_is_four(self):
        result = validate(_base_manifest())
        assert result.auto_checks_total == 4


# ---------------------------------------------------------------------------
# test_medium_confidence_critical_requires_review
# ---------------------------------------------------------------------------

class TestMediumConfidenceCritical:
    def test_medium_confidence_critical_requires_review(self):
        finding = _finding_dict(
            rule_id="NEXUM-002",
            severity="CRITICAL",
            confidence="MEDIUM",
        )
        manifest = _base_manifest(
            nexum_risk_score=25,
            findings_summary=[finding],
        )
        result = validate(manifest)
        assert result.verdict == "REVIEW_REQUIRED"
        assert "REVIEW_REQUIRED" in result.flags

    def test_critical_high_confidence_is_distributable(self):
        finding = _finding_dict(severity="CRITICAL", confidence="HIGH")
        manifest = _base_manifest(
            nexum_risk_score=25,
            findings_summary=[finding],
        )
        result = validate(manifest)
        assert result.verdict == "DISTRIBUTABLE"

    def test_high_severity_medium_confidence_is_distributable(self):
        # Only CRITICAL+MEDIUM triggers REVIEW_REQUIRED — HIGH+MEDIUM does not
        finding = _finding_dict(severity="HIGH", confidence="MEDIUM")
        manifest = _base_manifest(
            nexum_risk_score=10,
            findings_summary=[finding],
        )
        result = validate(manifest)
        assert result.verdict == "DISTRIBUTABLE"


# ---------------------------------------------------------------------------
# test_score_mismatch_triggers_do_not_distribute
# ---------------------------------------------------------------------------

class TestScoreMismatch:
    def test_score_mismatch_triggers_do_not_distribute(self):
        finding = _finding_dict(severity="HIGH")  # worth 10 pts
        manifest = _base_manifest(
            nexum_risk_score=99,              # wrong — should be 10
            findings_summary=[finding],
        )
        result = validate(manifest)
        assert result.verdict == "DO_NOT_DISTRIBUTE"
        assert "SCORE_MISMATCH" in result.flags

    def test_correct_score_no_mismatch_flag(self):
        finding = _finding_dict(severity="HIGH")
        manifest = _base_manifest(
            nexum_risk_score=10,
            findings_summary=[finding],
        )
        result = validate(manifest)
        assert "SCORE_MISMATCH" not in result.flags

    def test_score_cap_respected_in_mismatch_check(self):
        # 5 × CRITICAL (5 × 25 = 125) → capped at 100; manifest says 100 → no mismatch
        findings = [_finding_dict(severity="CRITICAL")] * 5
        manifest = _base_manifest(
            nexum_risk_score=100,
            findings_summary=findings,
        )
        result = validate(manifest)
        assert "SCORE_MISMATCH" not in result.flags


# ---------------------------------------------------------------------------
# test_known_false_positive_is_flagged
# ---------------------------------------------------------------------------

class TestKnownFalsePositive:
    def test_known_false_positive_is_flagged(self):
        finding = _finding_dict(
            rule_id="NEXUM-003",
            path="/api/resource/default",
            confidence="HIGH",
        )
        manifest = _base_manifest(
            nexum_risk_score=10,
            findings_summary=[finding],
        )
        result = validate(manifest)
        assert "LIKELY_FALSE_POSITIVE" in result.flags

    def test_non_matching_finding_not_flagged_as_fp(self):
        finding = _finding_dict(
            rule_id="NEXUM-003",
            path="/api/resource/list",  # does not match /default$ or /primary$
            confidence="HIGH",
        )
        manifest = _base_manifest(
            nexum_risk_score=10,
            findings_summary=[finding],
        )
        result = validate(manifest)
        assert "LIKELY_FALSE_POSITIVE" not in result.flags


# ---------------------------------------------------------------------------
# test_incomplete_data_flag_on_reconstructed_finding
# ---------------------------------------------------------------------------

class TestIncompleteData:
    def test_incomplete_data_flag_on_reconstructed_finding(self):
        # NEXUM-002 entry uses match_field="rule_name", which IS present in
        # reconstructed findings — use a hypothetical entry that would need
        # evidence_snippet. We test directly via match_false_positive instead.
        finding_without_path: dict[str, Any] = {
            "rule_id": "NEXUM-003",
            "rule_name": "UnboundedScope",
            "severity": "HIGH",
            "method": "GET",
            "confidence": "HIGH",
            # "path" is intentionally absent
        }
        matched, incomplete = match_false_positive(finding_without_path)
        assert incomplete is True
        assert matched is None

    def test_incomplete_data_produces_flag_in_validate(self):
        # Build a finding for NEXUM-003 that is missing its path field
        finding_no_path: dict[str, Any] = {
            "rule_id": "NEXUM-003",
            "rule_name": "UnboundedScope",
            "severity": "HIGH",
            "method": "DELETE",
            "confidence": "HIGH",
        }
        manifest = _base_manifest(
            nexum_risk_score=10,
            findings_summary=[finding_no_path],
        )
        result = validate(manifest)
        assert "INCOMPLETE_DATA" in result.flags
        assert "LIKELY_FALSE_POSITIVE" not in result.flags


# ---------------------------------------------------------------------------
# Integrity angle edge cases
# ---------------------------------------------------------------------------

class TestIntegrityAngle:
    def test_missing_source_file_is_flagged(self):
        manifest = _base_manifest()
        del manifest["source_file"]
        result = validate(manifest)
        assert "MISSING_FIELD" in result.flags

    def test_invalid_scanned_at_is_flagged(self):
        manifest = _base_manifest(scanned_at="not-a-timestamp")
        result = validate(manifest)
        assert "MISSING_FIELD" in result.flags


# ---------------------------------------------------------------------------
# DO_NOT_DISTRIBUTE — low confidence
# ---------------------------------------------------------------------------

class TestLowConfidence:
    def test_low_confidence_finding_triggers_do_not_distribute(self):
        finding = _finding_dict(severity="HIGH", confidence="LOW")
        manifest = _base_manifest(
            nexum_risk_score=10,
            findings_summary=[finding],
        )
        result = validate(manifest)
        assert result.verdict == "DO_NOT_DISTRIBUTE"

    def test_critical_low_overrides_review_required(self):
        # CRITICAL+LOW → DO_NOT_DISTRIBUTE (priority 1), not REVIEW_REQUIRED
        finding = _finding_dict(severity="CRITICAL", confidence="LOW")
        manifest = _base_manifest(
            nexum_risk_score=25,
            findings_summary=[finding],
        )
        result = validate(manifest)
        assert result.verdict == "DO_NOT_DISTRIBUTE"


# ---------------------------------------------------------------------------
# Completeness angle
# ---------------------------------------------------------------------------

class TestCompletenessAngle:
    def test_completeness_empty_summary_with_nonzero_score(self):
        manifest = _base_manifest(nexum_risk_score=25, findings_summary=[])
        result = validate(manifest)
        assert "MISSING_FIELD" in result.flags

    def test_missing_manual_review_required_is_flagged(self):
        manifest = _base_manifest()
        del manifest["manual_review_required"]
        result = validate(manifest)
        assert "MISSING_FIELD" in result.flags

    def test_missing_auto_detected_invariants_is_flagged(self):
        manifest = _base_manifest()
        del manifest["auto_detected_invariants"]
        result = validate(manifest)
        assert "MISSING_FIELD" in result.flags
