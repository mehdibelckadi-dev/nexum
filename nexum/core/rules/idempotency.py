"""NEXUM-004 — IdempotencyMissing: mutating operations without an Idempotency-Key header."""

from __future__ import annotations

import json
from typing import Any

from .base import BaseRule, Finding

_MUTATING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH"})
_IDEMPOTENCY_HEADER = "idempotency-key"

# TD-016: Path/operationId tokens that mark a financial / irreversible domain.
# A duplicate mutation here has no trivial remedy inside the spec (chargebacks,
# regulatory exposure), so NEXUM-004 escalates HIGH -> CRITICAL when matched.
_FINANCIAL_PATH_PATTERNS: frozenset[str] = frozenset({
    "charge", "charges",
    "payment", "payments",
    "invoice", "invoices",
    "refund", "refunds",
    "transfer", "transfers",
    "payout", "payouts",
    "withdraw", "withdrawal", "withdrawals",
    "billing",
    "subscription", "subscriptions",
})

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


def _is_financial_domain(path: str, operation_id: str = "") -> bool:
    """Detect financial/irreversible domain for NEXUM-004 severity escalation.

    Path segments use EXACT match (a segment must equal a known pattern) to
    avoid substring false positives such as 'exchanges' matching 'charges'.
    operationId uses substring match because it is a deliberate, semantically
    explicit identifier (e.g. 'createCharge', 'refundPayment').
    """
    segments = [s.lower() for s in path.strip("/").split("/") if s and "{" not in s]
    if any(seg in _FINANCIAL_PATH_PATTERNS for seg in segments):
        return True
    if operation_id:
        op_lower = operation_id.lower()
        return any(pattern in op_lower for pattern in _FINANCIAL_PATH_PATTERNS)
    return False


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

                if _is_financial_domain(path, op_id):
                    severity = "CRITICAL"
                    _expl = (
                        f"{_expl} Financial domain detected — duplicate execution "
                        "risk includes chargebacks, regulatory exposure, and customer "
                        "dispute costs beyond simple data correction."
                    )
                else:
                    severity = self.SEVERITY

                findings.append(Finding(
                    rule_id=self.RULE_ID,
                    rule_name=self.RULE_NAME,
                    severity=severity,
                    path=path,
                    method=method.upper(),
                    evidence_snippet=json.dumps(snippet, indent=2),
                    human_explanation=_expl,
                    guardrail_suggestion=_sugg,
                ))

        return findings
