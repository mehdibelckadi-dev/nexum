"""NEXUM-002 — DestructiveAmbiguity: destructive operations without a specific resource ID."""

from __future__ import annotations

import json
import re
from typing import Any

from .base import BaseRule, Finding

_DESTRUCTIVE_KEYWORDS: frozenset[str] = frozenset({
    "delete", "remove", "erase", "destroy", "drop", "purge", "wipe", "clear", "truncate",
})

# Matches common ID-like field names: id, uuid, _id, file_id, userId, etc.
_ID_NAME_RE = re.compile(
    r"^id$|^uuid$|_id$|_uuid$|^.+id$",
    re.IGNORECASE,
)


def _path_has_id_param(path: str) -> bool:
    return bool(re.search(r"\{[^}]+\}", path))


def _method_is_destructive(method: str, operation: dict[str, Any]) -> bool:
    if method.upper() == "DELETE":
        return True
    # MCP tools are normalised to POST; treat as destructive when the name says so.
    if operation.get("x-mcp-tool") and method.upper() == "POST":
        op_id = operation.get("operationId", "").lower()
        return any(kw in op_id for kw in _DESTRUCTIVE_KEYWORDS)
    return False


def _schema_has_required_id(schema: dict[str, Any]) -> bool:
    return any(_ID_NAME_RE.match(field) for field in schema.get("required", []))


class DestructiveAmbiguity(BaseRule):
    """Flags destructive operations that do not target a specific resource by ID."""

    RULE_ID = "NEXUM-002"
    RULE_NAME = "DestructiveAmbiguity"
    SEVERITY = "CRITICAL"

    def check(self, spec: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        for path, path_item in spec.get("paths", {}).items():
            for method, operation in path_item.items():
                if not isinstance(operation, dict):
                    continue
                if not _method_is_destructive(method, operation):
                    continue

                if method.upper() == "DELETE":
                    if not _path_has_id_param(path):
                        findings.append(self._finding_openapi(path, method, operation))

                elif operation.get("x-mcp-tool"):
                    body_schema = (
                        operation
                        .get("requestBody", {})
                        .get("content", {})
                        .get("application/json", {})
                        .get("schema", {})
                    )
                    if not _schema_has_required_id(body_schema):
                        findings.append(self._finding_mcp(path, operation, body_schema))

        return findings

    def _finding_openapi(self, path: str, method: str, operation: dict[str, Any]) -> Finding:
        snippet = {
            "path": path,
            "method": "DELETE",
            "parameters": operation.get("parameters", []),
        }
        return Finding(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            severity=self.SEVERITY,
            path=path,
            method="DELETE",
            evidence_snippet=json.dumps(snippet, indent=2),
            human_explanation=(
                f"DELETE {path} has no path parameter containing a resource identifier. "
                "The operation may target the entire collection or an ambiguous subset "
                "of resources, making it impossible for the agent to reason about scope."
            ),
            guardrail_suggestion=(
                "Add a required path parameter that unambiguously identifies the target "
                "resource, e.g. DELETE /{resource_id}. Reject requests that omit it."
            ),
        )

    def _finding_mcp(
        self, path: str, operation: dict[str, Any], schema: dict[str, Any]
    ) -> Finding:
        snippet = {
            "path": path,
            "operationId": operation.get("operationId", ""),
            "inputSchema": schema,
        }
        return Finding(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            severity=self.SEVERITY,
            path=path,
            method="POST",
            evidence_snippet=json.dumps(snippet, indent=2),
            human_explanation=(
                f"MCP tool '{operation.get('operationId')}' performs a destructive operation "
                "but its inputSchema has no required ID-like field (e.g. 'id', 'file_id', 'uuid'). "
                "Without an explicit identifier the agent cannot confirm the exact resource targeted."
            ),
            guardrail_suggestion=(
                "Add a required 'id' (or '<resource>_id') property to the tool's inputSchema "
                "and validate that it refers to exactly one existing resource before executing."
            ),
        )
