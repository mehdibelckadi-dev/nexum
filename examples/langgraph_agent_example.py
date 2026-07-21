"""Example: a LangGraph agent gated by the Nexum guardrail node.

This shows how Nexum's deterministic Trust Manifest (Layer 1) plugs into a real
agent framework as a decision-time guardrail. The graph has three nodes:

    prepare_call  → the "agent" decides which API/tool to call
    nexum_guardrail → reads the Trust Manifest and decides allow/approve/block
    execute_call  → runs the tool call ONLY if the guardrail approved it

No external API is ever called and no LLM sits inside the guardrail — the LLM of
a real agent would live in prepare_call, outside the guardrail decision.

Run it:

    pip install -e ".[langgraph]"      # or: pip install langgraph
    python examples/langgraph_agent_example.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, TypedDict

try:
    from langgraph.checkpoint.memory import MemorySaver
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import Command
except ModuleNotFoundError:
    print(
        "This example requires langgraph.\n"
        "  Install it with:  pip install -e \".[langgraph]\"   (or: pip install langgraph)"
    )
    sys.exit(1)

from nexum.integrations.langgraph_guardrail import nexum_guardrail_node

MANIFESTS = Path(__file__).parent / "manifests"


# ---- Typed agent state ----


class AgentState(TypedDict, total=False):
    api_name: str
    target_api_manifest_path: str
    tool_call: dict[str, Any]
    guardrail_decision: Any
    guardrail_approved: bool
    error: str | None
    result: str


# ---- Nodes ----


def prepare_call(state: AgentState) -> AgentState:
    """The agent decides which tool call to make.

    In a real agent this is where the LLM would plan the call — deliberately kept
    outside the guardrail, which stays deterministic.
    """
    api = state.get("api_name", "unknown")
    tool_call = {"api": api, "method": "POST", "path": "/v1/charges", "args": {"amount": 5000}}
    print(f"[prepare_call] Agent wants to call: {tool_call['method']} {api}{tool_call['path']}")
    return {**state, "tool_call": tool_call}


def execute_call(state: AgentState) -> AgentState:
    """Execute the (simulated) tool call — only reached when the guardrail approves."""
    tool_call = state.get("tool_call", {})
    result = f"Executed {tool_call.get('method')} {tool_call.get('api')}{tool_call.get('path')} (simulated)"
    print(f"[execute_call] {result}")
    return {**state, "result": result}


def route_after_guardrail(state: AgentState) -> str:
    """Conditional edge: proceed to execute only if the guardrail approved."""
    return "execute" if state.get("guardrail_approved") else "end"


# ---- Graph ----


def build_graph():
    builder = StateGraph(AgentState)
    builder.add_node("prepare_call", prepare_call)
    builder.add_node("nexum_guardrail", nexum_guardrail_node)
    builder.add_node("execute_call", execute_call)

    builder.add_edge(START, "prepare_call")
    builder.add_edge("prepare_call", "nexum_guardrail")
    builder.add_conditional_edges(
        "nexum_guardrail", route_after_guardrail, {"execute": "execute_call", "end": END}
    )
    builder.add_edge("execute_call", END)

    # A checkpointer is required for interrupt()/resume to work.
    return builder.compile(checkpointer=MemorySaver())


def _print_decision(state: dict[str, Any]) -> None:
    decision = state.get("guardrail_decision")
    if decision is not None:
        print(f"[nexum_guardrail] action={decision.action} — {decision.reason}")
    if state.get("error"):
        print(f"[result] BLOCKED/REJECTED: {state['error']}")
    elif state.get("result"):
        print(f"[result] OK: {state['result']}")


def _banner(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def run_scenarios() -> None:
    graph = build_graph()

    # --- Scenario 1: Tier 0 → allow, runs straight through ---
    _banner("Scenario 1 — Tier 0 (safe API): expect ALLOW")
    config = {"configurable": {"thread_id": "scenario-1"}}
    state = graph.invoke(
        {"api_name": "status.example.com",
         "target_api_manifest_path": str(MANIFESTS / "safe_api_manifest.json")},
        config,
    )
    _print_decision(state)

    # --- Scenario 2: Tier 2 → interrupt, human approves ---
    _banner("Scenario 2 — Tier 2 (Stripe): expect HUMAN APPROVAL → approve")
    config = {"configurable": {"thread_id": "scenario-2"}}
    state = graph.invoke(
        {"api_name": "api.stripe.com",
         "target_api_manifest_path": str(MANIFESTS / "stripe_manifest.json")},
        config,
    )
    interrupts = state.get("__interrupt__")
    if interrupts:
        payload = interrupts[0].value
        print(f"[interrupt] {payload['question']} "
              f"(tier={payload['risk_tier']}, score={payload['risk_score']})")
        print("[human] Approving the call...")
        state = graph.invoke(Command(resume={"approved": True}), config)
    _print_decision(state)

    # --- Scenario 3: Tier 2 → interrupt, human rejects ---
    _banner("Scenario 3 — Tier 2 (Stripe): expect HUMAN APPROVAL → reject")
    config = {"configurable": {"thread_id": "scenario-3"}}
    state = graph.invoke(
        {"api_name": "api.stripe.com",
         "target_api_manifest_path": str(MANIFESTS / "stripe_manifest.json")},
        config,
    )
    interrupts = state.get("__interrupt__")
    if interrupts:
        payload = interrupts[0].value
        print(f"[interrupt] {payload['question']} "
              f"(tier={payload['risk_tier']}, score={payload['risk_score']})")
        print("[human] Rejecting the call...")
        state = graph.invoke(Command(resume={"approved": False}), config)
    _print_decision(state)

    print()


if __name__ == "__main__":
    run_scenarios()
