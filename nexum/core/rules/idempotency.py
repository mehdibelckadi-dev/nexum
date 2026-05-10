"""NEXUM-004 — IdempotencyMissing: mutating operations without an Idempotency-Key header."""

from __future__ import annotations

import json
from typing import Any

from .base import BaseRule, Finding

_MUTATING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH"})
_IDEMPOTENCY_HEADER = "idempotency-key"

# MCP tool names that imply a read-only operation and should be skipped.
_READ_KEYWORDS: frozenset[str] = frozenset({
    "list", "get", "read", "fetch", "show", "describe", "find", "search", "query",
})


def _has_idempotency_header(operation: dict[str, Any]) -> bool:
    return any(
        isinstance(p, dict)
        and p.get("in") == "header"
        and p.get("name", "").lower() == _IDEMPOTENCY_HEADER
        for p in operation.get("parameters", [])
    )


def _is_mcp_read_only(operation: dict[str, Any]) -> bool:
    op_id = operation.get("operationId", "").lower()
    return any(kw in op_id for kw in _READ_KEYWORDS)


class IdempotencyMissing(BaseRule):
    """Flags mutating operations that lack an Idempotency-Key header."""

    RULE_ID = "NEXUM-004"
    RULE_NAME = "IdempotencyMissing"
    SEVERITY = "HIGH"

    def check(self, spec: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        for path, path_item in spec.get("paths", {}).items():
            for method, operation in path_item.items():
                if not isinstance(operation, dict):
                    continue
                if method.upper() not in _MUTATING_METHODS:
                    continue
                if operation.get("x-mcp-tool") and _is_mcp_read_only(operation):
                    continue
                if _has_idempotency_header(operation):
                    continue

                present_headers = [
                    p for p in operation.get("parameters", [])
                    if isinstance(p, dict) and p.get("in") == "header"
                ]
                snippet = {
                    "path": path,
                    "method": method.upper(),
                    "operationId": operation.get("operationId", ""),
                    "headers_present": present_headers,
                }
                findings.append(Finding(
                    rule_id=self.RULE_ID,
                    rule_name=self.RULE_NAME,
                    severity=self.SEVERITY,
                    path=path,
                    method=method.upper(),
                    evidence_snippet=json.dumps(snippet, indent=2),
                    human_explanation=(
                        f"{method.upper()} {path} accepts no Idempotency-Key header. "
                        "Network retries or agent replays can create duplicate resources "
                        "or apply the same mutation more than once without any safeguard."
                    ),
                    guardrail_suggestion=(
                        "Add 'Idempotency-Key' as a required request header. "
                        "The server must store the key and return the original response "
                        "for duplicate requests received within a reasonable window."
                    ),
                ))

        return findings
