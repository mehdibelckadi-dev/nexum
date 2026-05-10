"""Tests for core/scorer.py."""

from pathlib import Path

import pytest

from pact.core import engine
from pact.core.ingestor import ingest
from pact.core.rules.base import Finding
from pact.core.scorer import ScoreResult, _SEVERITY_POINTS, calculate

FIXTURES = Path(__file__).parent / "fixtures"


def _finding(severity: str) -> Finding:
    return Finding(
        rule_id="PACT-000",
        rule_name="Stub",
        severity=severity,
        path="/test",
        method="GET",
        evidence_snippet="{}",
        human_explanation="stub",
        guardrail_suggestion="stub",
    )


# ---------------------------------------------------------------------------
# Point values
# ---------------------------------------------------------------------------

class TestSeverityPoints:
    def test_critical_worth_25(self):
        result = calculate([_finding("CRITICAL")])
        assert result.score == 25

    def test_high_worth_10(self):
        result = calculate([_finding("HIGH")])
        assert result.score == 10

    def test_medium_worth_5(self):
        result = calculate([_finding("MEDIUM")])
        assert result.score == 5

    def test_low_worth_1(self):
        result = calculate([_finding("LOW")])
        assert result.score == 1

    def test_points_accumulate(self):
        findings = [_finding("CRITICAL"), _finding("HIGH"), _finding("MEDIUM"), _finding("LOW")]
        result = calculate(findings)
        assert result.score == 25 + 10 + 5 + 1


# ---------------------------------------------------------------------------
# Cap at 100
# ---------------------------------------------------------------------------

class TestScoreCap:
    def test_four_criticals_hit_exactly_100(self):
        result = calculate([_finding("CRITICAL")] * 4)
        assert result.score == 100

    def test_five_criticals_capped_at_100(self):
        result = calculate([_finding("CRITICAL")] * 5)
        assert result.score == 100

    def test_mixed_overflow_capped_at_100(self):
        findings = [_finding("CRITICAL")] * 3 + [_finding("HIGH")] * 5
        result = calculate(findings)
        assert result.score == 100

    def test_score_never_exceeds_100(self):
        findings = [_finding(s) for s in ["CRITICAL"] * 10 + ["HIGH"] * 10]
        assert calculate(findings).score <= 100


# ---------------------------------------------------------------------------
# Tier boundaries
# ---------------------------------------------------------------------------

class TestRiskTier:
    def test_empty_findings_tier_0(self):
        assert calculate([]).tier == 0
        assert calculate([]).score == 0

    def test_score_0_is_tier_0(self):
        assert calculate([]).tier == 0

    def test_score_30_is_tier_0(self):
        # 1×CRITICAL(25) + 1×MEDIUM(5) = 30
        result = calculate([_finding("CRITICAL"), _finding("MEDIUM")])
        assert result.score == 30
        assert result.tier == 0

    def test_score_31_is_tier_1(self):
        # 1×CRITICAL(25) + 1×MEDIUM(5) + 1×LOW(1) = 31
        result = calculate([_finding("CRITICAL"), _finding("MEDIUM"), _finding("LOW")])
        assert result.score == 31
        assert result.tier == 1

    def test_score_60_is_tier_1(self):
        # 2×CRITICAL(50) + 1×HIGH(10) = 60
        result = calculate([_finding("CRITICAL")] * 2 + [_finding("HIGH")])
        assert result.score == 60
        assert result.tier == 1

    def test_score_61_is_tier_2(self):
        # 2×CRITICAL(50) + 1×HIGH(10) + 1×LOW(1) = 61
        result = calculate([_finding("CRITICAL")] * 2 + [_finding("HIGH"), _finding("LOW")])
        assert result.score == 61
        assert result.tier == 2

    def test_score_100_is_tier_2(self):
        result = calculate([_finding("CRITICAL")] * 4)
        assert result.score == 100
        assert result.tier == 2


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------

class TestReturnType:
    def test_returns_score_result_instance(self):
        result = calculate([])
        assert isinstance(result, ScoreResult)

    def test_score_result_fields(self):
        result = calculate([_finding("HIGH")])
        assert hasattr(result, "score")
        assert hasattr(result, "tier")
        assert isinstance(result.score, int)
        assert isinstance(result.tier, int)

    def test_score_result_is_immutable(self):
        result = calculate([])
        with pytest.raises((AttributeError, TypeError)):
            result.score = 99  # type: ignore[misc]


# ---------------------------------------------------------------------------
# End-to-end: engine → scorer on real fixtures
# ---------------------------------------------------------------------------

class TestScorerWithFixtures:
    def test_openapi_fixture_score_and_tier(self):
        # 3×CRITICAL (PACT-001) = 75 → Tier 2
        spec = ingest(FIXTURES / "sample_openapi.yaml")
        findings = engine.run(spec)
        result = calculate(findings)
        assert result.score == 75
        assert result.tier == 2

    def test_mcp_fixture_score_and_tier(self):
        # PACT-002 CRITICAL(25) + PACT-004 HIGH(10) + PACT-005 MEDIUM(5) = 40 → Tier 1
        spec = ingest(FIXTURES / "sample_mcp.json")
        findings = engine.run(spec)
        result = calculate(findings)
        assert result.score == 40
        assert result.tier == 1

    def test_clean_spec_score_and_tier(self):
        spec = {"info": {}, "paths": {}, "components": {}, "_source_format": "openapi"}
        findings = engine.run(spec)
        result = calculate(findings)
        assert result.score == 0
        assert result.tier == 0
