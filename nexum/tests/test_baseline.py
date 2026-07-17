"""Tests for the baseline / suppression mechanism (nexum/core/baseline.py)."""

import json

import pytest

from nexum.core.baseline import (
    BaselineError,
    filter_baseline,
    finding_hash,
    generate_baseline,
    load_baseline,
)
from nexum.core.rules.base import Finding
from nexum.core.scorer import calculate


def _finding(**overrides) -> Finding:
    base = dict(
        rule_id="NEXUM-004",
        rule_name="IdempotencyMissing",
        severity="CRITICAL",
        path="/v1/charges",
        method="POST",
        evidence_snippet="POST /v1/charges",
        human_explanation="Mutation without an Idempotency-Key header.",
        guardrail_suggestion="Require an Idempotency-Key header.",
    )
    base.update(overrides)
    return Finding(**base)


class TestBaselineMechanism:
    def test_finding_hash_is_deterministic(self):
        f = _finding()
        assert finding_hash(f) == finding_hash(f)
        assert finding_hash(_finding()) == finding_hash(_finding())

    def test_finding_hash_stable_across_explanation_changes(self):
        f1 = _finding(human_explanation="A", evidence_snippet="X")
        f2 = _finding(human_explanation="B totally different", evidence_snippet="Y also different")
        assert finding_hash(f1) == finding_hash(f2)

    def test_filter_baseline_removes_matching_findings(self):
        f = _finding()
        baseline = {"version": "1.0", "entries": [{"hash": finding_hash(f)}]}
        active, _ = filter_baseline([f], baseline)
        assert f not in active
        assert active == []

    def test_filter_baseline_returns_suppressed_list(self):
        f = _finding()
        baseline = {"version": "1.0", "entries": [{"hash": finding_hash(f)}]}
        _, suppressed = filter_baseline([f], baseline)
        assert suppressed == [f]
        assert len(suppressed) == 1

    def test_score_recalculated_without_suppressed_findings(self):
        all_findings = [_finding(), _finding(path="/other", rule_id="NEXUM-002")]
        baseline = {"version": "1.0", "entries": [{"hash": finding_hash(all_findings[0])}]}
        active, _ = filter_baseline(all_findings, baseline)
        assert calculate(active).score < calculate(all_findings).score

    def test_generate_baseline_creates_valid_json(self, tmp_path):
        f1 = _finding()
        f2 = _finding(rule_id="NEXUM-002", path="/v1/refunds", severity="CRITICAL")
        out = tmp_path / ".nexumbaseline.json"
        generate_baseline([f1, f2], out)

        doc = json.loads(out.read_text())
        assert doc["version"] == "1.0"
        assert len(doc["entries"]) == 2
        for entry in doc["entries"]:
            for field in ("hash", "rule_id", "path", "method", "accepted_by", "accepted_at", "reason"):
                assert field in entry

    def test_load_baseline_rejects_invalid_schema(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"version": "1.0"}))  # missing 'entries'
        with pytest.raises(BaselineError):
            load_baseline(bad)

    def test_baseline_with_no_matches_is_noop(self, tmp_path):
        findings = [_finding()]
        out = tmp_path / ".nexumbaseline.json"
        # Generate a baseline for a DIFFERENT finding so nothing matches.
        generate_baseline([_finding(path="/unrelated", rule_id="NEXUM-001")], out)
        baseline = load_baseline(out)

        active, suppressed = filter_baseline(findings, baseline)
        assert active == findings
        assert suppressed == []
        assert calculate(active).score == calculate(findings).score
