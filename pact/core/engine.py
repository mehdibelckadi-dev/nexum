"""Engine: runs all PACT rules against a normalised spec and returns sorted Findings."""

from __future__ import annotations

from typing import Any

from .rules.auth_leakage import AuthLeakageRisk
from .rules.base import Finding
from .rules.destructive_ambiguity import DestructiveAmbiguity
from .rules.idempotency import IdempotencyMissing
from .rules.schema_volatility import SchemaVolatility
from .rules.unbounded_scope import UnboundedScope

_RULES = [
    AuthLeakageRisk(),
    DestructiveAmbiguity(),
    UnboundedScope(),
    IdempotencyMissing(),
    SchemaVolatility(),
]

_SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def run(spec: dict[str, Any]) -> list[Finding]:
    """Run every PACT rule and return all findings sorted by severity (CRITICAL first)."""
    findings: list[Finding] = []
    for rule in _RULES:
        findings.extend(rule.check(spec))
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
    return findings
