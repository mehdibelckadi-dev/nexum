"""Tests for core/scorer.py."""

from pathlib import Path

import pytest

from nexum.core import engine
from nexum.core.ingestor import ingest
from nexum.core.rules.base import Finding
from nexum.core.scorer import ScoreResult, _SEVERITY_POINTS, calculate

FIXTURES = Path(__file__).parent / "fixtures"


def _finding(severity: str, rule_id: str = "NEXUM-000") -> Finding:
    return Finding(
        rule_id=rule_id,
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
        # Distinct rule_ids so the per-rule cap (TD-017) does not drop any finding.
        findings = [
            _finding("CRITICAL", "NEXUM-001"),
            _finding("HIGH", "NEXUM-002"),
            _finding("MEDIUM", "NEXUM-003"),
            _finding("LOW", "NEXUM-004"),
        ]
        result = calculate(findings)
        assert result.score == 25 + 10 + 5 + 1


# ---------------------------------------------------------------------------
# Cap at 100
# ---------------------------------------------------------------------------

class TestScoreCap:
    def test_four_criticals_hit_exactly_100(self):
        # Distinct rule_ids so all four CRITICALs reach the score (TD-017 caps per rule).
        result = calculate([_finding("CRITICAL", f"NEXUM-00{i}") for i in range(4)])
        assert result.score == 100

    def test_five_criticals_capped_at_100(self):
        result = calculate([_finding("CRITICAL", f"NEXUM-00{i}") for i in range(5)])
        assert result.score == 100

    def test_mixed_overflow_capped_at_100(self):
        # One CRITICAL per distinct rule plus extra HIGHs, spread across rules so the
        # global 100 cap (not the per-rule cap) is what bounds the score.
        findings = [_finding("CRITICAL", f"NEXUM-0{i}") for i in range(8)]
        findings += [_finding("HIGH", f"NEXUM-1{i}") for i in range(5)]
        result = calculate(findings)
        assert result.score == 100

    def test_score_never_exceeds_100(self):
        findings = [_finding(s, f"NEXUM-{i}") for i, s in enumerate(["CRITICAL"] * 10 + ["HIGH"] * 10)]
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
        # 2×CRITICAL(50) + 1×HIGH(10) + 1×LOW(1) = 61. Distinct rule_ids so all four
        # findings count (TD-017 caps per rule, and a single rule holds only 2 here).
        findings = [
            _finding("CRITICAL", "NEXUM-001"),
            _finding("CRITICAL", "NEXUM-002"),
            _finding("HIGH", "NEXUM-003"),
            _finding("LOW", "NEXUM-004"),
        ]
        result = calculate(findings)
        assert result.score == 61
        assert result.tier == 2

    def test_score_100_is_tier_2(self):
        result = calculate([_finding("CRITICAL", f"NEXUM-00{i}") for i in range(4)])
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
        # 3×CRITICAL (NEXUM-001) = 75 → Tier 2
        spec = ingest(FIXTURES / "sample_openapi.yaml")
        findings = engine.run(spec)
        result = calculate(findings)
        assert result.score == 75
        assert result.tier == 2

    def test_mcp_fixture_score_and_tier(self):
        # NEXUM-002 CRITICAL(25) + NEXUM-004 HIGH(10) + NEXUM-005 MEDIUM(5) = 40 → Tier 1
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


# ---------------------------------------------------------------------------
# TD-017: per-rule score cap (max 3 instances per rule_id contribute to score)
# ---------------------------------------------------------------------------

class TestPerRuleScoreCap:
    def test_score_caps_at_three_instances_per_rule(self):
        # 210 HIGH findings of the same rule_id contribute at most 3 × 10 = 30,
        # not 210 × 10 = 2100.
        findings = [_finding("HIGH", "NEXUM-004")] * 210
        result = calculate(findings)
        assert result.score == 3 * _SEVERITY_POINTS["HIGH"]
        assert result.score == 30

    def test_score_before_after_digitalocean_case(self):
        # Real case: DigitalOcean produced 210 HIGH findings of NEXUM-004.
        findings = [_finding("HIGH", "NEXUM-004")] * 210

        # Behaviour BEFORE the fix: every instance summed, unbounded by rule.
        raw_before = len(findings) * _SEVERITY_POINTS["HIGH"]
        assert raw_before == 2100
        # ...which the old 100 global cap then saturated to a flat 100.
        scored_before = min(100, raw_before)
        assert scored_before == 100

        # Behaviour AFTER the fix: per-rule cap of 3 instances.
        scored_after = calculate(findings).score
        assert scored_after == 30

        # Documented evidence of the behavioural change for this case.
        assert scored_before - scored_after == 70

    def test_different_rule_ids_each_get_own_cap(self):
        # 5 findings of NEXUM-002 and 5 of NEXUM-004. Severities here are HIGH on
        # both purely to exercise cap mechanics; what matters is that each rule_id
        # caps to 3 instances INDEPENDENTLY — the cap is not shared across rules.
        findings = [_finding("HIGH", "NEXUM-002")] * 5 + [_finding("HIGH", "NEXUM-004")] * 5
        result = calculate(findings)
        # Each rule contributes 3 × 10 = 30 → 60 total.
        # A shared cap would give 30; no cap at all would give 100.
        assert result.score == 60

    def test_below_cap_threshold_unaffected(self):
        # Only 2 findings of the same rule (2 < 3): identical to pre-fix behaviour.
        findings = [_finding("HIGH", "NEXUM-004")] * 2
        result = calculate(findings)
        assert result.score == 20

    def test_severity_ordering_within_cap(self):
        # 7 instances of one rule_id: 5 HIGH then 2 CRITICAL (CRITICAL placed LAST
        # on purpose). The cap must keep the 2 highest-severity (CRITICAL) plus 1
        # HIGH = 25 + 25 + 10 = 60. A buggy "first 3 by appearance" would take the
        # 3 leading HIGHs = 30. This proves sorting happens BEFORE the cap.
        findings = [_finding("HIGH", "NEXUM-004")] * 5 + [_finding("CRITICAL", "NEXUM-004")] * 2
        result = calculate(findings)
        assert result.score == 60
