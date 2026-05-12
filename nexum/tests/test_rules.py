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
from nexum.core.scorer import calculate

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

    def test_patch_singleton_default_not_flagged(self):
        """PATCH on a /default singleton must not generate a finding.

        /default names a single well-known resource, not a collection.
        NEXUM-003 (UnboundedScope) only applies to operations that could
        affect an unbounded set of resources — singletons are out of scope.
        """
        spec = _minimal_spec(**{
            "/v2/projects/default": {
                "patch": {"operationId": "patchDefaultProject", "parameters": []}
            }
        })
        assert self.rule.check(spec) == []

    def test_delete_singleton_primary_not_flagged(self):
        """DELETE on a /primary singleton must not generate a finding."""
        spec = _minimal_spec(**{
            "/v2/accounts/primary": {
                "delete": {"operationId": "deletePrimaryAccount", "parameters": []}
            }
        })
        assert self.rule.check(spec) == []


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


class TestIdempotencyMissingMcpAnnotations:
    """NEXUM-004 behaviour driven by real MCP protocol annotations.

    Annotation values are taken verbatim from @modelcontextprotocol/server-filesystem
    v0.6.3 (tools/list response). Each test documents the exact precedence rule
    being exercised so the intent is clear without the original conversation.
    """

    rule = IdempotencyMissing()

    def _mcp_spec(self, tool_name: str, annotations: dict) -> dict:
        """Build a normalised spec identical to what _normalize_mcp produces."""
        relevant = {"readOnlyHint", "idempotentHint", "destructiveHint", "openWorldHint"}
        op: dict = {
            "operationId": tool_name,
            "description": "",
            "parameters": [],
            "requestBody": {"content": {"application/json": {"schema": {}}}},
            "x-mcp-tool": True,
        }
        filtered = {k: v for k, v in annotations.items() if k in relevant}
        if filtered:
            op["x-mcp-annotations"] = filtered
        return {
            "info": {}, "components": {}, "_source_format": "mcp",
            "paths": {f"/tools/{tool_name}": {"post": op}},
        }

    def test_write_file_idempotent_hint_not_flagged(self):
        """write_file: idempotentHint=true, destructiveHint=true → no finding.

        idempotentHint takes precedence: a retry writes the same content and
        reaches the same state, so no Idempotency-Key is needed.
        """
        spec = self._mcp_spec("write_file", {
            "readOnlyHint": False, "idempotentHint": True, "destructiveHint": True,
        })
        assert self.rule.check(spec) == []

    def test_directory_tree_readonly_hint_not_flagged(self):
        """directory_tree: readOnlyHint=true → no finding.

        readOnlyHint signals the tool never mutates state; NEXUM-004 only
        applies to operations that can change server-side data.
        """
        spec = self._mcp_spec("directory_tree", {"readOnlyHint": True})
        assert self.rule.check(spec) == []

    def test_edit_file_destructive_not_idempotent_flagged(self):
        """edit_file: idempotentHint=false, destructiveHint=true → NEXUM-004 finding.

        Neither skip condition is met: the operation is not read-only and a
        retry can apply the same edit twice, corrupting the file.
        """
        spec = self._mcp_spec("edit_file", {
            "readOnlyHint": False, "idempotentHint": False, "destructiveHint": True,
        })
        findings = self.rule.check(spec)
        assert len(findings) == 1
        assert findings[0].rule_id == "NEXUM-004"
        assert findings[0].path == "/tools/edit_file"

    def test_destructive_only_hint_still_flagged(self):
        """destructiveHint=true with no idempotentHint key present → NEXUM-004 finding.

        Validates that destructiveHint alone does not suppress the finding.
        Missing idempotentHint is not the same as idempotentHint=true; the
        rule must not treat absence of a hint as an implicit skip signal.
        """
        spec = self._mcp_spec("purge_cache", {"destructiveHint": True})
        findings = self.rule.check(spec)
        assert len(findings) == 1
        assert findings[0].rule_id == "NEXUM-004"
        assert findings[0].path == "/tools/purge_cache"

    def test_slack_reply_to_thread_flagged(self):
        """slack_reply_to_thread → must generate NEXUM-004 finding.

        Token-based matching splits on '_': tokens = {'slack', 'reply', 'to', 'thread'}.
        None of those equal a _READ_KEYWORDS entry, so the tool is not suppressed.
        Old substring matching incorrectly suppressed this because 'read' is a
        substring of 'thread'.
        """
        spec = self._mcp_spec("slack_reply_to_thread", {})
        findings = self.rule.check(spec)
        assert len(findings) == 1
        assert findings[0].rule_id == "NEXUM-004"
        assert findings[0].path == "/tools/slack_reply_to_thread"

    def test_slack_read_messages_not_flagged(self):
        """slack_read_messages → must NOT generate finding.

        Tokens = {'slack', 'read', 'messages'}. 'read' is an exact token match
        in _READ_KEYWORDS, so the tool is correctly suppressed.
        """
        spec = self._mcp_spec("slack_read_messages", {})
        assert self.rule.check(spec) == []

    def test_write_query_flagged(self):
        """write_query → must generate NEXUM-004 finding.

        SQLite mutation: accepts DELETE, UPDATE, INSERT. 'query' removed from
        _READ_KEYWORDS because it is not a reliable read-only indicator.
        """
        spec = self._mcp_spec("write_query", {})
        findings = self.rule.check(spec)
        assert len(findings) == 1
        assert findings[0].rule_id == "NEXUM-004"

    def test_delete_query_flagged(self):
        """delete_query → must generate NEXUM-004 finding.

        'query' as a standalone token must not suppress a tool whose name
        also contains an explicit mutation verb.
        """
        spec = self._mcp_spec("delete_query", {})
        findings = self.rule.check(spec)
        assert len(findings) == 1
        assert findings[0].rule_id == "NEXUM-004"

    def test_search_query_not_flagged(self):
        """search_query → must NOT generate finding.

        Tokens = {'search', 'query'}. 'search' is in _READ_KEYWORDS, so the
        tool is suppressed regardless of 'query' being present or absent.
        """
        spec = self._mcp_spec("search_query", {})
        assert self.rule.check(spec) == []

    def test_exec_query_flagged(self):
        """exec_query → must generate NEXUM-004 finding.

        'exec' is not in _READ_KEYWORDS and 'query' no longer suppresses.
        An execution tool is a mutation by nature.
        """
        spec = self._mcp_spec("exec_query", {})
        findings = self.rule.check(spec)
        assert len(findings) == 1
        assert findings[0].rule_id == "NEXUM-004"

    def test_git_status_not_flagged(self):
        """git_status → must NOT generate finding.

        Tokens = {'git', 'status'}. 'status' is now in _READ_KEYWORDS.
        """
        spec = self._mcp_spec("git_status", {})
        assert self.rule.check(spec) == []

    def test_git_diff_not_flagged(self):
        """git_diff → must NOT generate finding.

        Tokens = {'git', 'diff'}. 'diff' is now in _READ_KEYWORDS.
        """
        spec = self._mcp_spec("git_diff", {})
        assert self.rule.check(spec) == []

    def test_git_log_not_flagged(self):
        """git_log → must NOT generate finding.

        Tokens = {'git', 'log'}. 'log' is now in _READ_KEYWORDS.
        """
        spec = self._mcp_spec("git_log", {})
        assert self.rule.check(spec) == []

    def test_git_create_branch_flagged(self):
        """git_create_branch → must generate NEXUM-004 finding.

        Tokens = {'git', 'create', 'branch'}. 'branch' is intentionally absent
        from _READ_KEYWORDS: adding it would suppress git_create_branch, which
        is a write operation. None of the three tokens match a read keyword,
        so the finding is correctly generated.
        """
        spec = self._mcp_spec("git_create_branch", {})
        findings = self.rule.check(spec)
        assert len(findings) == 1
        assert findings[0].rule_id == "NEXUM-004"

    def test_git_reset_explanation_mentions_staging_area(self):
        """git_reset NEXUM-004 finding must use the per-operation override, not
        the generic template. 'staging area' appears only in the override text —
        its presence confirms _OPERATION_EXPLANATIONS is wired correctly.
        """
        spec = self._mcp_spec("git_reset", {})
        findings = self.rule.check(spec)
        assert len(findings) == 1
        assert "staging area" in findings[0].human_explanation


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


# ---------------------------------------------------------------------------
# --exclude-path filtering (CLI contract, tested at the domain layer)
# ---------------------------------------------------------------------------

class TestExcludePathFiltering:
    """Verify that filtering findings by path before scoring works correctly.

    These tests exercise the same logic the CLI applies between engine.run()
    and calculate(): filter by exact path membership, then recalculate score.
    """

    def _run_with_exclusions(self, spec: dict, excluded: set[str]):
        findings = engine.run(spec)
        filtered = [f for f in findings if f.path not in excluded]
        return findings, filtered, calculate(filtered)

    def test_score_lower_with_exclusion(self):
        """Excluding findings that exist reduces the risk score."""
        spec = ingest(FIXTURES / "sample_openapi.yaml")
        full_findings = engine.run(spec)
        assert full_findings, "fixture must produce at least one finding"

        path_to_exclude = full_findings[0].path
        filtered = [f for f in full_findings if f.path != path_to_exclude]

        full_score = calculate(full_findings).score
        filtered_score = calculate(filtered).score

        assert filtered_score < full_score

    def test_excluded_path_absent_from_filtered_findings(self):
        """The excluded path must not appear in the filtered list."""
        spec = ingest(FIXTURES / "sample_openapi.yaml")
        full_findings = engine.run(spec)
        path_to_exclude = full_findings[0].path

        filtered = [f for f in full_findings if f.path != path_to_exclude]

        assert not any(f.path == path_to_exclude for f in filtered)

    def test_nonexistent_path_exclusion_is_noop(self):
        """Excluding a path with no findings leaves findings and score unchanged."""
        spec = ingest(FIXTURES / "sample_openapi.yaml")
        full_findings = engine.run(spec)
        ghost_path = "/does/not/exist/in/spec"

        filtered = [f for f in full_findings if f.path != ghost_path]

        assert filtered == full_findings
        assert calculate(filtered).score == calculate(full_findings).score

    def test_multiple_exclude_paths(self):
        """Excluding two distinct paths removes findings from both."""
        spec = _minimal_spec(**{
            "/alpha": {
                "delete": {"operationId": "deleteAlpha", "parameters": []},
            },
            "/beta": {
                "delete": {"operationId": "deleteBeta", "parameters": []},
            },
        })
        full_findings = engine.run(spec)
        paths_present = {f.path for f in full_findings}
        assert "/alpha" in paths_present
        assert "/beta" in paths_present

        excluded = {"/alpha", "/beta"}
        filtered = [f for f in full_findings if f.path not in excluded]

        assert all(f.path not in excluded for f in filtered)
        assert calculate(filtered).score < calculate(full_findings).score
