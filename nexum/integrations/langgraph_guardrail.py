"""LangGraph guardrail node backed by a pre-generated Nexum Trust Manifest.

Before an agent executes a tool call against an external API, this node reads the
Trust Manifest that Nexum's deterministic core (Layer 1) already produced for that
API and decides:

- ``allow``                  — the agent proceeds without intervention
- ``require_human_approval`` — LangGraph ``interrupt()`` for human-in-the-loop
- ``block``                  — the tool call is not executed; the agent gets an error

This node is NOT an HTTP gateway. It does not intercept live traffic and it does
not call any external endpoint — it only reads a manifest already on disk. The
decision is fully deterministic (no LLM), following the same fail-closed principle
as NEXUM-002: absence of a risk profile blocks the call rather than assuming safety.

``langgraph`` is an optional dependency. It is imported lazily inside the
``require_human_approval`` branch so this module stays importable — and the
``allow``/``block`` paths stay usable — without langgraph installed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ---- Decision types ----


@dataclass
class GuardrailDecision:
    action: str          # "allow" | "require_human_approval" | "block"
    reason: str
    tier: int | None
    score: int | None


# ---- Manifest loading ----


def load_manifest(manifest_path: str | Path) -> dict | None:
    """Load a pre-generated Nexum Trust Manifest from disk.

    Returns None if the file doesn't exist — treated as block (fail-closed).
    """
    path = Path(manifest_path)
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


# ---- Core guardrail logic ----


def evaluate_manifest(manifest: dict | None) -> GuardrailDecision:
    """Deterministic decision from a Trust Manifest.

    No LLM involved. Same fail-closed principle as NEXUM-002.
    """
    if manifest is None:
        return GuardrailDecision(
            action="block",
            reason="No Trust Manifest found for this API. "
                   "Fail-closed: agent cannot proceed without a risk profile.",
            tier=None,
            score=None,
        )

    tier = manifest.get("inferred_risk_tier", 2)
    score = manifest.get("nexum_risk_score", 100)

    if tier == 0:
        return GuardrailDecision(
            action="allow",
            reason=f"Tier 0 — no critical risk patterns detected. Score: {score}/100.",
            tier=tier,
            score=score,
        )
    elif tier == 1:
        return GuardrailDecision(
            action="allow",
            reason=f"Tier 1 — moderate risk patterns detected. Score: {score}/100. "
                   "Proceeding with caution.",
            tier=tier,
            score=score,
        )
    else:  # tier == 2
        return GuardrailDecision(
            action="require_human_approval",
            reason=f"Tier 2 — HIGH RISK. Score: {score}/100. "
                   "Human approval required before agent can call this API.",
            tier=tier,
            score=score,
        )


# ---- LangGraph node ----


def nexum_guardrail_node(state: dict[str, Any]) -> dict[str, Any]:
    """LangGraph node that evaluates the Nexum Trust Manifest for the target API
    before allowing the agent to make a tool call.

    Expected state keys:
    - target_api_manifest_path: str — path to the .nexum-manifest.json
    - tool_call: dict — the tool call the agent wants to execute

    Returns state with added keys:
    - guardrail_decision: GuardrailDecision
    - guardrail_approved: bool
    """
    manifest_path = state.get("target_api_manifest_path", "")
    manifest = load_manifest(manifest_path)
    decision = evaluate_manifest(manifest)

    if decision.action == "block":
        return {
            **state,
            "guardrail_decision": decision,
            "guardrail_approved": False,
            "error": decision.reason,
        }

    if decision.action == "require_human_approval":
        # Lazy import: langgraph is an optional dependency, only needed for the
        # human-in-the-loop path. Keeps the module importable (and the allow/block
        # paths usable) without langgraph installed.
        from langgraph.types import interrupt

        # LangGraph interrupt() — pauses the graph and waits for human input.
        human_response = interrupt({
            "question": "Nexum detected HIGH RISK for this API call. Approve?",
            "risk_tier": decision.tier,
            "risk_score": decision.score,
            "reason": decision.reason,
            "tool_call": state.get("tool_call"),
        })
        approved = human_response.get("approved", False)
        return {
            **state,
            "guardrail_decision": decision,
            "guardrail_approved": approved,
            "error": None if approved else "Human reviewer rejected the API call.",
        }

    # action == "allow"
    return {
        **state,
        "guardrail_decision": decision,
        "guardrail_approved": True,
        "error": None,
    }
