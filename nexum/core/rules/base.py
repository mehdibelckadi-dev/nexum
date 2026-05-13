"""Base abstractions shared by all Nexum rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    rule_id: str           # e.g. "NEXUM-001"
    rule_name: str         # e.g. "AuthLeakageRisk"
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    path: str              # API path that triggered the rule
    method: str            # HTTP method (upper-case)
    evidence_snippet: str  # exact fragment from the spec that fired the rule
    human_explanation: str
    guardrail_suggestion: str
    confidence: str = "HIGH"        # HIGH | MEDIUM | LOW
    confidence_reason: str = ""     # why this confidence level was assigned


class BaseRule(ABC):
    """Every rule must implement check() and return a (possibly empty) list of Findings."""

    @abstractmethod
    def check(self, spec: dict[str, Any]) -> list[Finding]:
        """Analyse a normalised spec dict and return zero or more Findings."""
