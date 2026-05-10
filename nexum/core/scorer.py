"""Risk scorer: converts a list of Findings into a capped score and a Risk Tier."""

from __future__ import annotations

from dataclasses import dataclass

from .rules.base import Finding

_SEVERITY_POINTS: dict[str, int] = {
    "CRITICAL": 25,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 1,
}

_MAX_SCORE = 100


@dataclass(frozen=True)
class ScoreResult:
    score: int  # 0–100
    tier: int   # 0 | 1 | 2


def _tier(score: int) -> int:
    if score <= 30:
        return 0
    if score <= 60:
        return 1
    return 2


def calculate(findings: list[Finding]) -> ScoreResult:
    """Sum severity points, cap at 100, and assign a Risk Tier."""
    total = sum(_SEVERITY_POINTS.get(f.severity, 0) for f in findings)
    score = min(_MAX_SCORE, total)
    return ScoreResult(score=score, tier=_tier(score))
