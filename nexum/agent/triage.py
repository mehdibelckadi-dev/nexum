"""LLM triage layer for NEXUM reports — fail-closed, strictly additive.

This is the ONLY module in NEXUM that calls an LLM. It can never read, alter,
infer, or recompute severity, score, or tier — those are owned by the
deterministic engine. A strict allowlist (never a denylist) enforces
fail-closed parsing: the entire response is rejected on any unexpected field.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any

import anthropic

log = logging.getLogger(__name__)

ALLOWED_FIELDS: frozenset[str] = frozenset(
    {"finding_id", "priority_explanation", "remediation_suggestion"}
)

_MODEL = "claude-haiku-4-5"
_MAX_TOKENS = 2048
_GENERIC_UNAVAILABLE = (
    "Triage prioritization unavailable for this report. "
    "Deterministic findings and risk score are unaffected."
)


class TriageResponseError(Exception):
    """Raised when the LLM response contains disallowed fields, is missing
    required fields, or otherwise fails the allowlist. Fail-closed: the entire
    response is rejected, never silently filtered."""


class TriageFailureCategory(str, Enum):
    OPERATIONAL = "operational"  # timeout, rate limit, network failure
    INTEGRITY = "integrity"      # disallowed fields, invalid schema, malformed JSON


@dataclass(frozen=True)
class TriageUnavailable:
    reason: str                      # generic text — the ONLY field shown to the user
    category: TriageFailureCategory  # internal only — never surfaced to the user


@dataclass(frozen=True)
class TriageItem:
    finding_id: str
    priority_explanation: str
    remediation_suggestion: str


@dataclass(frozen=True)
class Report:
    """Deterministic manifest plus an additive, never-load-bearing triage section."""
    manifest: dict[str, Any]
    triage_section: list[TriageItem] | TriageUnavailable | None


def build_prompt(manifest: dict[str, Any]) -> str:
    schema_example = json.dumps(
        [{
            "finding_id": "NEXUM-002@/v1/charges",
            "priority_explanation": "Why this finding should be remediated first.",
            "remediation_suggestion": "Concrete fix to apply.",
        }],
        indent=2,
    )
    return (
        "You are a triage assistant for a deterministic security scanner.\n"
        "Do NOT alter, infer, recompute, or output severity or score values — "
        "they are owned by the deterministic engine and are not yours to touch.\n"
        "Your ONLY job is to rank the given findings by remediation priority and "
        "suggest fixes.\n"
        "Output PURE JSON only — no preamble, no markdown fences — a list whose "
        "every item has EXACTLY these three keys and no others:\n"
        f"{schema_example}\n\n"
        "Manifest under triage:\n"
        f"{json.dumps(manifest, indent=2)}"
    )


def call_agent(prompt: str) -> str:
    """Single Haiku call returning the raw text. Network, timeout, and
    rate-limit exceptions PROPAGATE to the command layer — not caught here."""
    client = anthropic.Anthropic()
    message = client.messages.create(
        model=_MODEL,
        max_tokens=_MAX_TOKENS,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(b.text for b in message.content if b.type == "text")


def parse_response(raw: str) -> list[TriageItem]:
    """Fail-closed allowlist parser. Rejects the ENTIRE response on any
    disallowed or missing field. JSONDecodeError propagates uncaught."""
    data = json.loads(raw)  # JSONDecodeError propagates — intentional
    items: list[TriageItem] = []
    for entry in data:
        keys = set(entry.keys())
        rejected = keys - ALLOWED_FIELDS
        if rejected:
            raise TriageResponseError(
                f"LLM response contained disallowed fields: {sorted(rejected)}. "
                "Entire response rejected — fail-closed policy."
            )
        missing = ALLOWED_FIELDS - keys
        if missing:
            raise TriageResponseError(
                f"LLM response missing required fields: {sorted(missing)}."
            )
        items.append(TriageItem(
            finding_id=entry["finding_id"],
            priority_explanation=entry["priority_explanation"],
            remediation_suggestion=entry["remediation_suggestion"],
        ))
    return items


def generate_report(manifest: dict[str, Any], include_triage: bool = True) -> Report:
    """Command layer — graceful degradation. The deterministic manifest is
    ALWAYS returned unchanged; the triage section is best-effort and additive.
    Failures are categorised internally (OPERATIONAL vs INTEGRITY) for logs
    only; the user-facing `reason` is always the same generic text."""
    triage_section: list[TriageItem] | TriageUnavailable | None = None
    if include_triage:
        try:
            raw = call_agent(build_prompt(manifest))
            triage_section = parse_response(raw)
        except (TriageResponseError, json.JSONDecodeError) as exc:
            triage_section = TriageUnavailable(
                reason=_GENERIC_UNAVAILABLE,
                category=TriageFailureCategory.INTEGRITY,
            )
            log.warning("[triage.integrity] %s", exc)
        except anthropic.APIError as exc:
            triage_section = TriageUnavailable(
                reason=_GENERIC_UNAVAILABLE,
                category=TriageFailureCategory.OPERATIONAL,
            )
            log.warning("[triage.operational] %s", exc)
    return Report(manifest=manifest, triage_section=triage_section)
