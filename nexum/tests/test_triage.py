"""Tests for the LLM triage layer (nexum/agent/triage.py).

The triage layer is fail-closed and strictly additive: it can never alter the
deterministic manifest, and any unexpected field rejects the whole response.
No test here touches the real Anthropic API — call_agent is always mocked.
"""

import json

import anthropic
import httpx
import pytest

from nexum.agent import triage
from nexum.agent.triage import (
    TriageFailureCategory,
    TriageResponseError,
    TriageUnavailable,
    parse_response,
)

_VALID_ITEM = {
    "finding_id": "NEXUM-002@/v1/charges",
    "priority_explanation": "Duplicate charge has no trivial remedy.",
    "remediation_suggestion": "Require an Idempotency-Key header.",
}

_MANIFEST = {
    "nexum_risk_score": 40,
    "inferred_risk_tier": 1,
    "findings_summary": [{"rule_id": "NEXUM-002", "severity": "CRITICAL"}],
}


# ---------------------------------------------------------------------------
# Layer 1 — parse_response (fail-closed allowlist)
# ---------------------------------------------------------------------------

class TestParseResponse:
    def test_llm_injected_severity_raises_not_logs(self):
        # The LLM tries to smuggle severity/score back in — reject the whole
        # response, do not silently filter and continue.
        raw = json.dumps([{**_VALID_ITEM, "severity": "CRITICAL", "score": 99}])
        with pytest.raises(TriageResponseError) as exc:
            parse_response(raw)
        assert "disallowed fields" in str(exc.value)
        assert "severity" in str(exc.value)

    def test_llm_missing_required_field_raises(self):
        raw = json.dumps([{
            "finding_id": "X",
            "priority_explanation": "p",
            # remediation_suggestion missing
        }])
        with pytest.raises(TriageResponseError) as exc:
            parse_response(raw)
        assert "missing required fields" in str(exc.value)
        assert "remediation_suggestion" in str(exc.value)

    def test_valid_response_with_exact_allowed_fields_succeeds(self):
        items = parse_response(json.dumps([_VALID_ITEM]))
        assert len(items) == 1
        assert items[0].finding_id == "NEXUM-002@/v1/charges"
        # The TriageItem carries ONLY the three allowed fields — no leakage of
        # deterministic axes into the agent-produced object.
        assert not hasattr(items[0], "severity")
        assert not hasattr(items[0], "score")

    def test_malformed_json_propagates_jsondecodeerror(self):
        # Not valid JSON — the error propagates uncaught (fail-closed), it is
        # not swallowed into a partial/empty result.
        with pytest.raises(json.JSONDecodeError):
            parse_response("{not valid json")


# ---------------------------------------------------------------------------
# Layer 2 — generate_report (graceful degradation)
# ---------------------------------------------------------------------------

class TestGenerateReportDegradation:
    def test_command_degrades_gracefully_on_integrity_error(self, monkeypatch):
        monkeypatch.setattr(triage, "call_agent", lambda _p: "[]")

        def _raise(_raw):
            raise TriageResponseError("disallowed fields: ['severity']")

        monkeypatch.setattr(triage, "parse_response", _raise)

        report = triage.generate_report(_MANIFEST)
        assert report is not None
        # Deterministic report intact.
        assert report.manifest["nexum_risk_score"] == 40
        assert report.manifest["inferred_risk_tier"] == 1
        # Triage degraded, categorised INTEGRITY internally.
        assert isinstance(report.triage_section, TriageUnavailable)
        assert report.triage_section.category is TriageFailureCategory.INTEGRITY

    def test_command_degrades_gracefully_on_operational_error(self, monkeypatch):
        request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")

        def _raise(_p):
            raise anthropic.APIConnectionError(message="network down", request=request)

        monkeypatch.setattr(triage, "call_agent", _raise)

        report = triage.generate_report(_MANIFEST)
        assert report.manifest["nexum_risk_score"] == 40
        assert isinstance(report.triage_section, TriageUnavailable)
        assert report.triage_section.category is TriageFailureCategory.OPERATIONAL

    def test_user_facing_reason_never_exposes_category_or_internals(self, monkeypatch):
        # Integrity path.
        monkeypatch.setattr(triage, "call_agent", lambda _p: "[]")
        monkeypatch.setattr(
            triage, "parse_response",
            lambda _r: (_ for _ in ()).throw(TriageResponseError("disallowed fields: severity")),
        )
        integ = triage.generate_report(_MANIFEST).triage_section

        # Operational path.
        request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
        monkeypatch.setattr(
            triage, "call_agent",
            lambda _p: (_ for _ in ()).throw(
                anthropic.APIConnectionError(message="boom", request=request)
            ),
        )
        oper = triage.generate_report(_MANIFEST).triage_section

        # Both report the same generic, category-agnostic text.
        assert integ.reason == oper.reason
        reason = integ.reason.lower()
        for leak in (
            "integrity", "operational", "disallowed",
            "traceback", "apiconnectionerror", "severity",
        ):
            assert leak not in reason

    def test_successful_triage_does_not_block_deterministic_report(self, monkeypatch):
        monkeypatch.setattr(
            triage, "call_agent", lambda _p: json.dumps([_VALID_ITEM])
        )
        with_triage = triage.generate_report(_MANIFEST, include_triage=True)
        without = triage.generate_report(_MANIFEST, include_triage=False)

        # The deterministic manifest is identical whether or not triage runs.
        assert with_triage.manifest == without.manifest
        # Triage is purely additive: present when on, absent when off.
        assert isinstance(with_triage.triage_section, list)
        assert without.triage_section is None
