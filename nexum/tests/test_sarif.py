"""Tests for the SARIF 2.1.0 formatter (nexum/core/formatters/sarif.py)."""

import json

from nexum.core.formatters.sarif import to_sarif
from nexum.core.rules.base import Finding


def _finding(severity="CRITICAL", **overrides) -> Finding:
    base = dict(
        rule_id="NEXUM-001",
        rule_name="AuthLeakageRisk",
        severity=severity,
        path="/invoices",
        method="GET",
        evidence_snippet="api_key in query",
        human_explanation="Credential exposed in query string.",
        guardrail_suggestion="Move the credential to an Authorization header.",
    )
    base.update(overrides)
    return Finding(**base)


class TestSarifFormatter:
    def test_sarif_output_has_correct_schema_version(self):
        out = to_sarif([_finding()], "spec.yaml")
        assert out["version"] == "2.1.0"
        assert "sarif-2.1.0" in out["$schema"]

    def test_sarif_rules_include_all_five_nexum_rules(self):
        out = to_sarif([], "spec.yaml")
        rules = out["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 5
        assert {r["id"] for r in rules} == {
            "NEXUM-001",
            "NEXUM-002",
            "NEXUM-003",
            "NEXUM-004",
            "NEXUM-005",
        }

    def test_critical_finding_maps_to_error_level(self):
        out = to_sarif([_finding(severity="CRITICAL")], "spec.yaml")
        assert out["runs"][0]["results"][0]["level"] == "error"

    def test_high_finding_maps_to_warning_level(self):
        out = to_sarif([_finding(severity="HIGH")], "spec.yaml")
        assert out["runs"][0]["results"][0]["level"] == "warning"

    def test_evidence_snippet_appears_in_region(self):
        out = to_sarif([_finding(evidence_snippet="SECRET_TOKEN_XYZ")], "spec.yaml")
        region = out["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["snippet"]["text"] == "SECRET_TOKEN_XYZ"

    def test_path_and_method_in_logical_location(self):
        out = to_sarif([_finding(method="DELETE", path="/droplets")], "spec.yaml")
        logical = out["runs"][0]["results"][0]["locations"][0]["logicalLocations"][0]
        assert logical["decoratedName"] == "DELETE /droplets"

    def test_empty_findings_produces_valid_sarif(self):
        out = to_sarif([], "spec.yaml")
        assert out["runs"][0]["results"] == []
        assert len(out["runs"][0]["tool"]["driver"]["rules"]) == 5

    def test_sarif_is_valid_json(self):
        # Must serialise to JSON without raising.
        serialised = json.dumps(to_sarif([_finding()], "spec.yaml"))
        assert json.loads(serialised)["version"] == "2.1.0"
