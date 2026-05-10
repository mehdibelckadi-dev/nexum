"""NEXUM-005 — SchemaVolatility: additionalProperties: true in mutation request schemas."""

from __future__ import annotations

import json
from typing import Any

from .base import BaseRule, Finding

_MUTATING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH"})


def _allows_additional_properties(schema: dict[str, Any]) -> bool:
    """Return True if the schema (or any nested object schema) has additionalProperties: true."""
    if not isinstance(schema, dict):
        return False
    if schema.get("additionalProperties") is True:
        return True
    for sub in schema.get("properties", {}).values():
        if _allows_additional_properties(sub):
            return True
    items = schema.get("items")
    if isinstance(items, dict) and _allows_additional_properties(items):
        return True
    return False


def _request_body_schema(operation: dict[str, Any]) -> dict[str, Any] | None:
    schema = (
        operation
        .get("requestBody", {})
        .get("content", {})
        .get("application/json", {})
        .get("schema")
    )
    return schema if isinstance(schema, dict) else None


class SchemaVolatility(BaseRule):
    """Flags mutating operations whose request schema permits arbitrary extra fields."""

    RULE_ID = "NEXUM-005"
    RULE_NAME = "SchemaVolatility"
    SEVERITY = "MEDIUM"

    def check(self, spec: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        for path, path_item in spec.get("paths", {}).items():
            for method, operation in path_item.items():
                if not isinstance(operation, dict):
                    continue
                if method.upper() not in _MUTATING_METHODS:
                    continue

                schema = _request_body_schema(operation)
                if schema is None or not _allows_additional_properties(schema):
                    continue

                snippet = {
                    "path": path,
                    "method": method.upper(),
                    "schema": schema,
                }
                findings.append(Finding(
                    rule_id=self.RULE_ID,
                    rule_name=self.RULE_NAME,
                    severity=self.SEVERITY,
                    path=path,
                    method=method.upper(),
                    evidence_snippet=json.dumps(snippet, indent=2),
                    human_explanation=(
                        f"{method.upper()} {path} accepts a request body with "
                        "'additionalProperties: true'. An AI agent can inject arbitrary "
                        "fields that the server may silently persist, forward, or act on "
                        "in ways not visible in the spec."
                    ),
                    guardrail_suggestion=(
                        "Set 'additionalProperties: false' and enumerate every allowed "
                        "property explicitly. Reject requests containing unknown fields "
                        "at the API boundary before they reach business logic."
                    ),
                ))

        return findings
