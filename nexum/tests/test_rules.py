"""Tests for all five Nexum rule implementations and the engine."""

from pathlib import Path
from typing import Any

import pytest

from nexum.core import engine
from nexum.core.engine import _SEVERITY_ORDER
from nexum.core.ingestor import ingest
from nexum.core.rules.auth_leakage import AuthLeakageRisk
from nexum.core.rules.base import Finding
from nexum.core.rules.destructive_ambiguity import DestructiveAmbiguity
from nexum.core.rules.unbounded_scope import UnboundedScope
from nexum.core.rules.idempotency import IdempotencyMissing
from nexum.core.rules.schema_volatility import SchemaVolatility

FIXTURES = Path(__file__).parent / "fixtures"


def _minimal_spec(**paths: Any) -> dict[str, Any]:
    return {"info": {}, "paths": paths, "components": {}, "_source_format": "openapi"}


# ---------------------------------------------------------------------------
# NEXUM-001  AuthLeakageRisk
# ---------------------------------------------------------------------------

class TestAuthLeakageRisk:
    rule = AuthLeakageRisk()

    def test_detects_api_key_in_query(self):
        spec = ingest(FIXTURES / "sample_openapi.yaml")
        findings = self.rule.check(spec)
        assert len(findings) >= 2

    def test_finding_fields_are_correct(self):
        spec = ingest(FIXTURES / "sample_openapi.yaml")
        for f in self.rule.check(spec):
            assert f.rule_id == "NEXUM-001"
            assert f.rule_name == "AuthLeakageRisk"
            assert f.severity == "CRITICAL"
            assert f.method in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
            assert '"in": "query"' in f.evidence_snippet
            assert f.human_explanation != ""
            assert f.guardrail_suggestion != ""

    def test_evidence_snippet_is_full_param_object(self):
        spec = ingest(FIXTURES / "sample_openapi.yaml")
        for f in self.rule.check(spec):
            import json
            obj = json.loads(f.evidence_snippet)
            assert "name" in obj
            assert "in" in obj
            assert obj["in"] == "query"
            assert "schema" in obj

    def test_paths_with_credentials_are_flagged(self):
        spec = ingest(FIXTURES / "sample_openapi.yaml")
        flagged = {f.path for f in self.rule.check(spec)}
        assert "/invoices" in flagged
        assert "/invoices/{invoice_id}" in flagged

    def test_clean_delete_endpoint_not_flagged(self):
        spec = ingest(FIXTURES / "sample_openapi.yaml")
        delete_findings = [f for f in self.rule.check(spec) if f.path == "/users/{user_id}"]
        assert delete_findings == []

    def test_mcp_spec_returns_no_findings(self):
        spec = ingest(FIXTURES / "sample_mcp.json")
        assert self.rule.check(spec) == []

    def test_empty_spec_returns_no_findings(self):
        assert self.rule.check(_minimal_spec()) == []


# ---------------------------------------------------------------------------
# NEXUM-002  DestructiveAmbiguity
# ---------------------------------------------------------------------------

class TestDestructiveAmbiguity:
    rule = DestructiveAmbiguity()

    def test_delete_without_path_param_is_flagged(self):
        spec = _minimal_spec(**{
            "/files": {"delete": {"operationId": "deleteAll", "parameters": []}}
        })
        findings = self.rule.check(spec)
        assert len(findings) == 1
        assert findings[0].rule_id == "NEXUM-002"
        assert findings[0].severity == "CRITICAL"
        assert findings[0].path == "/files"
        assert findings[0].method == "DELETE"

    def test_delete_with_path_param_not_flagged(self):
        spec = _minimal_spec(**{
            "/files/{file_id}": {
                "delete": {
                    "operationId": "deleteFile",
                    "parameters": [{"name": "file_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                }
            }
        })
        assert self.rule.check(spec) == []

    def test_openapi_fixture_delete_has_path_param(self):
        """DELETE /users/{user_id} carries an explicit ID — must not be flagged."""
        spec = ingest(FIXTURES / "sample_openapi.yaml")
        assert self.rule.check(spec) == []

    def test_mcp_delete_without_id_is_flagged(self):
        spec = ingest(FIXTURES / "sample_mcp.json")
        flagged = [f for f in self.rule.check(spec) if "delete_files" in f.path]
        assert len(flagged) == 1
        assert flagged[0].severity == "CRITICAL"
        assert flagged[0].method == "POST"

    def test_mcp_read_tools_not_flagged(self):
        spec = ingest(FIXTURES / "sample_mcp.json")
        findings = self.rule.check(spec)
        non_delete = [f for f in findings if "delete" not in f.path]
        assert non_delete == []

    def test_evidence_snippet_contains_path_and_method(self):
        spec = _minimal_spec(**{
            "/items": {"delete": {"operationId": "deleteItems", "parameters": []}}
        })
        f = self.rule.check(spec)[0]
        import json
        obj = json.loads(f.evidence_snippet)
        assert obj["path"] == "/items"
        assert obj["method"] == "DELETE"


# ---------------------------------------------------------------------------
# NEXUM-003  UnboundedScope
# ---------------------------------------------------------------------------

class TestUnboundedScope:
    rule = UnboundedScope()

    def test_delete_without_param_or_filter_is_flagged(self):
        spec = _minimal_spec(**{
            "/logs": {"delete": {"operationId": "deleteLogs", "parameters": []}}
        })
        findings = self.rule.check(spec)
        assert len(findings) == 1
        assert findings[0].rule_id == "NEXUM-003"
        assert findings[0].severity == "HIGH"

    def test_patch_without_param_or_filter_is_flagged(self):
        spec = _minimal_spec(**{
            "/settings": {"patch": {"operationId": "patchSettings", "parameters": []}}
        })
        findings = self.rule.check(spec)
        assert len(findings) == 1
        assert findings[0].method == "PATCH"

    def test_wildcard_default_param_is_flagged(self):
        spec = _minimal_spec(**{
            "/records": {
                "delete": {
                    "operationId": "deleteRecords",
                    "parameters": [
                        {"name": "filter", "in": "query", "required": False,
                         "schema": {"type": "string", "default": "*"}},
                    ],
                }
            }
        })
        findings = self.rule.check(spec)
        assert len(findings) == 1
        import json
        obj = json.loads(findings[0].evidence_snippet)
        assert obj["trigger"] == "wildcard_param"

    def test_delete_with_path_param_not_flagged(self):
        spec = _minimal_spec(**{
            "/logs/{log_id}": {
                "delete": {
                    "operationId": "deleteLog",
                    "parameters": [{"name": "log_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                }
            }
        })
        assert self.rule.check(spec) == []

    def test_delete_with_required_query_filter_not_flagged(self):
        spec = _minimal_spec(**{
            "/logs": {
                "delete": {
                    "operationId": "deleteLogs",
                    "parameters": [{"name": "before_date", "in": "query", "required": True, "schema": {"type": "string"}}],
                }
            }
        })
        assert self.rule.check(spec) == []

    def test_openapi_fixture_has_no_unbounded_scope(self):
        """All DELETE/PATCH in the fixture are already scoped."""
        spec = ingest(FIXTURES / "sample_openapi.yaml")
        assert self.rule.check(spec) == []

    def test_get_operations_not_checked(self):
        spec = _minimal_spec(**{
            "/items": {"get": {"operationId": "listItems", "parameters": []}}
        })
        assert self.rule.check(spec) == []

    def test_mcp_fixture_returns_empty_list_without_exception(self):
        """MCP tools are normalised to POST; NEXUM-003 only checks DELETE/PATCH.
        The rule must return [] cleanly — no exception, no false positive."""
        spec = ingest(FIXTURES / "sample_mcp.json")
        result = self.rule.check(spec)
        assert result == []


# ---------------------------------------------------------------------------
# NEXUM-004  IdempotencyMissing
# ---------------------------------------------------------------------------

class TestIdempotencyMissing:
    rule = IdempotencyMissing()

    def test_post_without_idempotency_header_flagged(self):
        spec = _minimal_spec(**{
            "/payments": {"post": {"operationId": "createPayment", "parameters": []}}
        })
        findings = self.rule.check(spec)
        assert len(findings) == 1
        assert findings[0].rule_id == "NEXUM-004"
        assert findings[0].severity == "HIGH"
        assert findings[0].method == "POST"

    def test_post_with_idempotency_header_not_flagged(self):
        spec = _minimal_spec(**{
            "/payments": {
                "post": {
                    "operationId": "createPayment",
                    "parameters": [
                        {"name": "Idempotency-Key", "in": "header", "required": True,
                         "schema": {"type": "string"}},
                    ],
                }
            }
        })
        assert self.rule.check(spec) == []

    def test_idempotency_header_check_is_case_insensitive(self):
        spec = _minimal_spec(**{
            "/orders": {
                "post": {
                    "operationId": "createOrder",
                    "parameters": [
                        {"name": "idempotency-key", "in": "header", "required": True,
                         "schema": {"type": "string"}},
                    ],
                }
            }
        })
        assert self.rule.check(spec) == []

    def test_put_and_patch_also_checked(self):
        spec = _minimal_spec(**{
            "/users/{id}": {
                "put": {"operationId": "replaceUser", "parameters": []},
                "patch": {"operationId": "updateUser", "parameters": []},
            }
        })
        findings = self.rule.check(spec)
        methods = {f.method for f in findings}
        assert "PUT" in methods
        assert "PATCH" in methods

    def test_get_and_delete_not_checked(self):
        spec = _minimal_spec(**{
            "/users/{id}": {
                "get": {"operationId": "getUser", "parameters": []},
                "delete": {"operationId": "deleteUser", "parameters": []},
            }
        })
        assert self.rule.check(spec) == []

    def test_openapi_fixture_no_mutating_methods(self):
        spec = ingest(FIXTURES / "sample_openapi.yaml")
        assert self.rule.check(spec) == []

    def test_mcp_destructive_tool_flagged(self):
        """delete_files is not read-only — must be flagged."""
        spec = ingest(FIXTURES / "sample_mcp.json")
        flagged = [f for f in self.rule.check(spec) if "delete_files" in f.path]
        assert len(flagged) == 1

    def test_mcp_read_only_tools_not_flagged(self):
        spec = ingest(FIXTURES / "sample_mcp.json")
        findings = self.rule.check(spec)
        read_findings = [
            f for f in findings
            if "list_files" in f.path or "read_file" in f.path
        ]
        assert read_findings == []


# ---------------------------------------------------------------------------
# NEXUM-005  SchemaVolatility
# ---------------------------------------------------------------------------

class TestSchemaVolatility:
    rule = SchemaVolatility()

    def test_post_with_additional_properties_true_flagged(self):
        spec = _minimal_spec(**{
            "/items": {
                "post": {
                    "operationId": "createItem",
                    "parameters": [],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "additionalProperties": True,
                                    "properties": {"name": {"type": "string"}},
                                }
                            }
                        }
                    },
                }
            }
        })
        findings = self.rule.check(spec)
        assert len(findings) == 1
        assert findings[0].rule_id == "NEXUM-005"
        assert findings[0].severity == "MEDIUM"

    def test_post_with_additional_properties_false_not_flagged(self):
        spec = _minimal_spec(**{
            "/items": {
                "post": {
                    "operationId": "createItem",
                    "parameters": [],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "properties": {"name": {"type": "string"}},
                                }
                            }
                        }
                    },
                }
            }
        })
        assert self.rule.check(spec) == []

    def test_nested_additional_properties_detected(self):
        spec = _minimal_spec(**{
            "/orders": {
                "post": {
                    "operationId": "createOrder",
                    "parameters": [],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "metadata": {
                                            "type": "object",
                                            "additionalProperties": True,
                                        }
                                    },
                                }
                            }
                        }
                    },
                }
            }
        })
        findings = self.rule.check(spec)
        assert len(findings) == 1

    def test_get_delete_not_checked(self):
        spec = _minimal_spec(**{
            "/items/{id}": {
                "get": {"operationId": "getItem", "parameters": []},
                "delete": {"operationId": "deleteItem", "parameters": []},
            }
        })
        assert self.rule.check(spec) == []

    def test_openapi_fixture_no_mutating_methods(self):
        spec = ingest(FIXTURES / "sample_openapi.yaml")
        assert self.rule.check(spec) == []

    def test_mcp_tool_with_additional_properties_flagged(self):
        """delete_files inputSchema has additionalProperties:true → flagged."""
        spec = ingest(FIXTURES / "sample_mcp.json")
        flagged = [f for f in self.rule.check(spec) if "delete_files" in f.path]
        assert len(flagged) == 1
        assert flagged[0].method == "POST"

    def test_mcp_tools_without_additional_properties_not_flagged(self):
        spec = ingest(FIXTURES / "sample_mcp.json")
        findings = self.rule.check(spec)
        clean = [f for f in findings if "list_files" in f.path or "read_file" in f.path]
        assert clean == []

    def test_evidence_snippet_contains_schema(self):
        spec = ingest(FIXTURES / "sample_mcp.json")
        for f in self.rule.check(spec):
            import json
            obj = json.loads(f.evidence_snippet)
            assert "schema" in obj
            assert obj["schema"].get("additionalProperties") is True


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

_ALL_RULES_SPEC: dict = {
    "_source_format": "openapi",
    "info": {},
    "components": {},
    "paths": {
        "/items": {
            # NEXUM-001: api_key in query
            # NEXUM-002: DELETE with no path param
            # NEXUM-003: DELETE with no path param and no required filter
            "delete": {
                "operationId": "deleteAll",
                "parameters": [
                    {"name": "api_key", "in": "query", "required": False,
                     "schema": {"type": "string"}},
                ],
            },
            # NEXUM-004: POST without Idempotency-Key
            # NEXUM-005: requestBody with additionalProperties: true
            "post": {
                "operationId": "createItem",
                "parameters": [],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"type": "object", "additionalProperties": True},
                        }
                    }
                },
            },
        }
    },
}


class TestEngine:
    def test_returns_list_of_finding_instances(self):
        spec = ingest(FIXTURES / "sample_openapi.yaml")
        result = engine.run(spec)
        assert isinstance(result, list)
        assert all(isinstance(f, Finding) for f in result)

    def test_empty_spec_returns_empty_list(self):
        assert engine.run({"info": {}, "paths": {}, "components": {}}) == []

    def test_openapi_fixture_finding_count_and_rule(self):
        # 3 findings: api_key on /invoices (×2) and /invoices/{invoice_id}
        spec = ingest(FIXTURES / "sample_openapi.yaml")
        findings = engine.run(spec)
        assert len(findings) == 3
        assert all(f.rule_id == "NEXUM-001" for f in findings)

    def test_mcp_fixture_finding_count(self):
        # NEXUM-002 (CRITICAL) + NEXUM-004 (HIGH) + NEXUM-005 (MEDIUM) on delete_files
        spec = ingest(FIXTURES / "sample_mcp.json")
        findings = engine.run(spec)
        assert len(findings) == 3

    def test_mcp_fixture_severity_order(self):
        spec = ingest(FIXTURES / "sample_mcp.json")
        findings = engine.run(spec)
        positions = [_SEVERITY_ORDER[f.severity] for f in findings]
        assert positions == sorted(positions), "Findings must be ordered CRITICAL → HIGH → MEDIUM"

    def test_mcp_fixture_severity_sequence(self):
        spec = ingest(FIXTURES / "sample_mcp.json")
        severities = [f.severity for f in engine.run(spec)]
        assert severities == ["CRITICAL", "HIGH", "MEDIUM"]

    def test_all_five_rules_can_fire(self):
        findings = engine.run(_ALL_RULES_SPEC)
        rule_ids = {f.rule_id for f in findings}
        assert rule_ids == {"NEXUM-001", "NEXUM-002", "NEXUM-003", "NEXUM-004", "NEXUM-005"}

    def test_all_five_rules_sorted_by_severity(self):
        findings = engine.run(_ALL_RULES_SPEC)
        positions = [_SEVERITY_ORDER[f.severity] for f in findings]
        assert positions == sorted(positions)

    def test_mixed_severities_sorted_correctly(self):
        # Deliberately trigger HIGH before CRITICAL in rule order to prove sort works
        spec = _minimal_spec(**{
            "/a": {"patch": {"operationId": "patchAll", "parameters": []}},   # NEXUM-003 HIGH
            "/b": {"delete": {"operationId": "deleteAll", "parameters": []}},  # NEXUM-002 CRITICAL + NEXUM-003 HIGH
        })
        findings = engine.run(spec)
        positions = [_SEVERITY_ORDER[f.severity] for f in findings]
        assert positions == sorted(positions)
