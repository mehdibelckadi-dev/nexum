"""Agent layer — the only part of NEXUM that may call an LLM.

Strictly additive and fail-closed: nothing here can read, alter, infer, or
recompute severity, score, or tier. Those remain owned by the deterministic
engine in nexum/core.
"""

from .triage import (
    ALLOWED_FIELDS,
    Report,
    TriageFailureCategory,
    TriageItem,
    TriageResponseError,
    TriageUnavailable,
    build_prompt,
    call_agent,
    generate_report,
    parse_response,
)

__all__ = [
    "ALLOWED_FIELDS",
    "Report",
    "TriageFailureCategory",
    "TriageItem",
    "TriageResponseError",
    "TriageUnavailable",
    "build_prompt",
    "call_agent",
    "generate_report",
    "parse_response",
]
