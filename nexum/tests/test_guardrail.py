"""Tests for the LangGraph guardrail node (nexum/integrations/langgraph_guardrail.py).

These tests exercise only the deterministic logic and the allow/block paths of the
node, so they pass without langgraph installed (the require_human_approval path,
which imports langgraph lazily, is not tested here).
"""

import json

from nexum.integrations.langgraph_guardrail import (
    evaluate_manifest,
    load_manifest,
    nexum_guardrail_node,
)


class TestNexumGuardrailNode:
    def test_tier0_manifest_returns_allow(self):
        manifest = {"inferred_risk_tier": 0, "nexum_risk_score": 0}
        decision = evaluate_manifest(manifest)
        assert decision.action == "allow"
        assert decision.tier == 0

    def test_tier2_manifest_returns_require_human_approval(self):
        manifest = {"inferred_risk_tier": 2, "nexum_risk_score": 100}
        decision = evaluate_manifest(manifest)
        assert decision.action == "require_human_approval"

    def test_missing_manifest_returns_block(self):
        decision = evaluate_manifest(None)
        assert decision.action == "block"
        assert decision.tier is None

    def test_load_manifest_returns_none_for_missing_file(self):
        result = load_manifest("/tmp/nonexistent_manifest.json")
        assert result is None

    def test_load_manifest_returns_dict_for_valid_file(self, tmp_path):
        manifest = {"inferred_risk_tier": 1, "nexum_risk_score": 50}
        path = tmp_path / "test_manifest.json"
        path.write_text(json.dumps(manifest))
        result = load_manifest(path)
        assert result["inferred_risk_tier"] == 1

    def test_block_decision_sets_error_in_state(self):
        state = {"target_api_manifest_path": "/nonexistent", "tool_call": {}}
        result = nexum_guardrail_node(state)
        assert result["guardrail_approved"] is False
        assert result["error"] is not None

    def test_allow_decision_sets_approved_true_in_state(self, tmp_path):
        manifest = {"inferred_risk_tier": 0, "nexum_risk_score": 0}
        path = tmp_path / "manifest.json"
        path.write_text(json.dumps(manifest))
        state = {"target_api_manifest_path": str(path), "tool_call": {}}
        result = nexum_guardrail_node(state)
        assert result["guardrail_approved"] is True
        assert result["error"] is None
