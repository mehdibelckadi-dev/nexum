"""NEXUM-004 — IdempotencyMissing: mutating operations without an Idempotency-Key header."""

from __future__ import annotations

import json
from typing import Any

from .base import BaseRule, Finding

_MUTATING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH"})
_IDEMPOTENCY_HEADER = "idempotency-key"

# MCP tool names that imply a read-only operation and should be skipped.
_READ_KEYWORDS: frozenset[str] = frozenset({
    "list", "get", "read", "fetch", "show", "describe", "find", "search",
    "status", "diff", "log",
})


def _has_idempotency_header(operation: dict[str, Any]) -> bool:
    return any(
        isinstance(p, dict)
        and p.get("in") == "header"
        and p.get("name", "").lower() == _IDEMPOTENCY_HEADER
        for p in operation.get("parameters", [])
    )


def _is_mcp_read_only(operation: dict[str, Any]) -> bool:
    tokens = set(operation.get("operationId", "").lower().split("_"))
    return any(kw in tokens for kw in _READ_KEYWORDS)


# Per-operation overrides for human_explanation and guardrail_suggestion.
# Detection logic is unchanged; only the analyst-facing text differs.
# TD-009: Move to shared data file when more than 5 entries exist.
_OPERATION_EXPLANATIONS: dict[str, tuple[str, str]] = {
    "git_reset": (
        "POST /tools/git_reset unstages ALL staged files in one call with no path "
        "scope. The tool is hardcoded to 'git reset HEAD' (mixed mode — working "
        "directory is not touched; --hard is not exposed). Without an Idempotency-Key "
        "a retry after a transient failure cannot determine whether the first call "
        "succeeded: if it did, all staged work accumulated through prior git_add "
        "calls has already been discarded, clearing the entire staging area.",
        "Add 'Idempotency-Key' as a required request header so callers can detect "
        "duplicate execution. Also consider accepting an explicit list of paths to "
        "unstage instead of resetting the entire index — this limits blast radius "
        "and makes the operation easier to reason about.",
    ),
}


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
                mcp_ann = operation.get("x-mcp-annotations", {})
                if mcp_ann:
                    # readOnlyHint: true → not a mutation, skip unconditionally.
                    if mcp_ann.get("readOnlyHint") is True:
                        continue
                    # idempotentHint: true → retry-safe by declaration, skip.
                    # Takes precedence over destructiveHint (e.g. write_file is
                    # destructive but idempotent — a retry produces the same state).
                    if mcp_ann.get("idempotentHint") is True:
                        continue
                    # annotations present but neither readOnlyHint nor idempotentHint
                    # is true → fall through to finding (e.g. edit_file with
                    # idempotentHint=false, destructiveHint=true).
                elif operation.get("x-mcp-tool") and _is_mcp_read_only(operation):
                    # No annotations present: fall back to keyword heuristic for
                    # tools that pre-date MCP annotation support.
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
                op_id = operation.get("operationId", "")
                _expl, _sugg = _OPERATION_EXPLANATIONS.get(op_id, (
                    f"{method.upper()} {path} accepts no Idempotency-Key header. "
                    "Network retries or agent replays can create duplicate resources "
                    "or apply the same mutation more than once without any safeguard.",
                    "Add 'Idempotency-Key' as a required request header. "
                    "The server must store the key and return the original response "
                    "for duplicate requests received within a reasonable window.",
                ))
                findings.append(Finding(
                    rule_id=self.RULE_ID,
                    rule_name=self.RULE_NAME,
                    severity=self.SEVERITY,
                    path=path,
                    method=method.upper(),
                    evidence_snippet=json.dumps(snippet, indent=2),
                    human_explanation=_expl,
                    guardrail_suggestion=_sugg,
                ))

        return findings
