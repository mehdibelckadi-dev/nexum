"""Tests for manifest/generator.py."""

from datetime import timezone
from pathlib import Path

import pytest

from pact.core import engine
from pact.core.ingestor import ingest
from pact.core.rules.base import Finding
from pact.core.scorer import ScoreResult, calculate
from pact.manifest.generator import (
    _REQUIRES_HUMAN_REVIEW,
    _extract_immutable_fields,
    _extract_numeric_limits,
    _extract_required_headers,
    generate,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _finding(severity: str, rule_id: str = "PACT-000", path: str = "/test", method: str = "GET") -> Finding:
    return Finding(
        rule_id=rule_id, rule_name="Stub", severity=severity,
        path=path, method=method, evidence_snippet="{}",
        human_explanation="stub", guardrail_suggestion="stub",
    )


def _result(score: int = 0, tier: int = 0) -> ScoreResult:
    return ScoreResult(score=score, tier=tier)


def _manifest(findings=None, result=None, source="test.yaml", spec=None):
    return generate(
        findings or [],
        result or _result(),
        source,
        spec or {"paths": {}, "components": {}},
    )


# ---------------------------------------------------------------------------
# Top-level fields
# ---------------------------------------------------------------------------

class TestManifestShape:
    def test_manifest_version(self):
        assert _manifest()["manifest_version"] == "1.0-draft"

    def test_source_file_preserved(self):
        assert _manifest(source="billing_api.yaml")["source_file"] == "billing_api.yaml"

    def test_scanned_at_is_iso_utc(self):
        ts = _manifest()["scanned_at"]
        from datetime import datetime
        dt = datetime.fromisoformat(ts)
        assert dt.tzinfo is not None

    def test_score_and_tier_from_result(self):
        m = _manifest(result=_result(score=75, tier=2))
        assert m["pact_risk_score"] == 75
        assert m["inferred_risk_tier"] == 2

    def test_model_compatibility_range_is_human_review(self):
        assert _manifest()["model_compatibility_range"] == _REQUIRES_HUMAN_REVIEW

    def test_required_keys_present(self):
        m = _manifest()
        for key in ("manifest_version", "scanned_at", "source_file",
                    "inferred_risk_tier", "pact_risk_score",
                    "model_compatibility_range", "auto_detected_invariants",
                    "findings_summary", "manual_review_required"):
            assert key in m, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# findings_summary
# ---------------------------------------------------------------------------

class TestFindingsSummary:
    def test_empty_findings_gives_empty_summary(self):
        assert _manifest()["findings_summary"] == []

    def test_summary_contains_expected_fields(self):
        f = _finding("CRITICAL", rule_id="PACT-001", path="/invoices", method="GET")
        summary = _manifest(findings=[f])["findings_summary"]
        assert len(summary) == 1
        entry = summary[0]
        assert entry["rule_id"] == "PACT-001"
        assert entry["severity"] == "CRITICAL"
        assert entry["path"] == "/invoices"
        assert entry["method"] == "GET"

    def test_summary_length_matches_findings(self):
        findings = [_finding("CRITICAL"), _finding("HIGH"), _finding("MEDIUM")]
        assert len(_manifest(findings=findings)["findings_summary"]) == 3

    def test_summary_preserves_order(self):
        findings = [
            _finding("CRITICAL", rule_id="PACT-001"),
            _finding("HIGH", rule_id="PACT-004"),
            _finding("MEDIUM", rule_id="PACT-005"),
        ]
        ids = [e["rule_id"] for e in _manifest(findings=findings)["findings_summary"]]
        assert ids == ["PACT-001", "PACT-004", "PACT-005"]


# ---------------------------------------------------------------------------
# manual_review_required
# ---------------------------------------------------------------------------

class TestManualReview:
    def test_model_compatibility_always_flagged(self):
        fields = [r["field"] for r in _manifest()["manual_review_required"]]
        assert "model_compatibility_range" in fields

    def test_immutable_fields_flagged_when_none_detected(self):
        fields = [r["field"] for r in _manifest()["manual_review_required"]]
        assert "auto_detected_invariants.immutable_fields" in fields

    def test_numeric_limits_flagged_when_none_detected(self):
        fields = [r["field"] for r in _manifest()["manual_review_required"]]
        assert "auto_detected_invariants.numeric_limits" in fields

    def test_immutable_fields_not_flagged_when_detected(self):
        spec = {
            "paths": {},
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "readOnly": True},
                            "name": {"type": "string"},
                        },
                    }
                }
            },
        }
        fields = [r["field"] for r in _manifest(spec=spec)["manual_review_required"]]
        assert "auto_detected_invariants.immutable_fields" not in fields

    def test_numeric_limits_not_flagged_when_detected(self):
        spec = {
            "paths": {},
            "components": {
                "schemas": {
                    "Item": {
                        "type": "object",
                        "properties": {
                            "quantity": {"type": "integer", "minimum": 1, "maximum": 999},
                        },
                    }
                }
            },
        }
        fields = [r["field"] for r in _manifest(spec=spec)["manual_review_required"]]
        assert "auto_detected_invariants.numeric_limits" not in fields

    def test_each_entry_has_field_and_reason(self):
        for entry in _manifest()["manual_review_required"]:
            assert "field" in entry
            assert "reason" in entry
            assert entry["reason"] != ""


# ---------------------------------------------------------------------------
# auto_detected_invariants extractors
# ---------------------------------------------------------------------------

class TestInvariantExtractors:
    def test_required_headers_extracted(self):
        spec = {
            "paths": {
                "/pay": {
                    "post": {
                        "parameters": [
                            {"name": "Idempotency-Key", "in": "header", "required": True,
                             "schema": {"type": "string"}},
                            {"name": "X-Trace-Id", "in": "header", "required": True,
                             "schema": {"type": "string"}},
                        ]
                    }
                }
            },
            "components": {},
        }
        headers = _extract_required_headers(spec)
        assert "Idempotency-Key" in headers
        assert "X-Trace-Id" in headers

    def test_optional_headers_excluded(self):
        spec = {
            "paths": {
                "/pay": {
                    "post": {
                        "parameters": [
                            {"name": "X-Optional", "in": "header", "required": False,
                             "schema": {"type": "string"}},
                        ]
                    }
                }
            },
            "components": {},
        }
        assert _extract_required_headers(spec) == []

    def test_immutable_fields_from_read_only(self):
        spec = {
            "paths": {},
            "components": {
                "schemas": {
                    "Record": {
                        "properties": {
                            "id": {"type": "string", "readOnly": True},
                            "created_at": {"type": "string", "readOnly": True},
                            "mutable": {"type": "string"},
                        }
                    }
                }
            },
        }
        fields = _extract_immutable_fields(spec)
        assert "id" in fields
        assert "created_at" in fields
        assert "mutable" not in fields

    def test_numeric_limits_from_constraints(self):
        spec = {
            "paths": {},
            "components": {
                "schemas": {
                    "Order": {
                        "properties": {
                            "quantity": {"type": "integer", "minimum": 1, "maximum": 100},
                            "note": {"type": "string", "maxLength": 500},
                        }
                    }
                }
            },
        }
        limits = _extract_numeric_limits(spec)
        assert "Order.quantity" in limits
        assert limits["Order.quantity"]["minimum"] == 1
        assert limits["Order.quantity"]["maximum"] == 100
        assert "Order.note" in limits
        assert limits["Order.note"]["maxLength"] == 500


# ---------------------------------------------------------------------------
# End-to-end with real fixtures
# ---------------------------------------------------------------------------

class TestManifestWithFixtures:
    def _run(self, fixture_path: str) -> dict:
        spec = ingest(fixture_path)
        findings = engine.run(spec)
        result = calculate(findings)
        return generate(findings, result, fixture_path, spec)

    def test_openapi_fixture_score_75_tier_2(self):
        m = self._run(str(FIXTURES / "sample_openapi.yaml"))
        assert m["pact_risk_score"] == 75
        assert m["inferred_risk_tier"] == 2

    def test_openapi_fixture_findings_summary_has_3_entries(self):
        m = self._run(str(FIXTURES / "sample_openapi.yaml"))
        assert len(m["findings_summary"]) == 3
        assert all(e["rule_id"] == "PACT-001" for e in m["findings_summary"])

    def test_mcp_fixture_score_40_tier_1(self):
        m = self._run(str(FIXTURES / "sample_mcp.json"))
        assert m["pact_risk_score"] == 40
        assert m["inferred_risk_tier"] == 1

    def test_mcp_fixture_findings_summary_rule_ids(self):
        m = self._run(str(FIXTURES / "sample_mcp.json"))
        ids = [e["rule_id"] for e in m["findings_summary"]]
        assert ids == ["PACT-002", "PACT-004", "PACT-005"]
