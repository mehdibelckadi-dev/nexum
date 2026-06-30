"""Risk scorer: converts a list of Findings into a capped score and a Risk Tier."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .rules.base import Finding

_SEVERITY_POINTS: dict[str, int] = {
    "CRITICAL": 25,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 1,
}

# Severity ranking reused from the rest of the codebase (engine.py / pdf_generator.py):
# lower number = higher severity. Used to order findings within a rule group so the
# per-rule score cap keeps the highest-severity instances first.
_SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# TD-017: at most this many instances of a single rule_id contribute to the score.
# The first occurrences establish that the problem is real and systemic; further
# occurrences add no new information to the score and only confirm what is already
# flagged. Capping them prevents artificial saturation and preserves the score's
# power to discriminate between APIs with concentrated vs. widespread problems.
# The cap is purely numeric: every real instance still appears in the manifest
# findings_summary and in the PDF.
_SCORE_CAP_PER_RULE = 3

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
    """Sum severity points (capped per rule_id), cap at 100, and assign a Risk Tier.

    Findings are grouped by rule_id; within each group the highest-severity
    instances are summed up to _SCORE_CAP_PER_RULE. The cap affects only the
    numeric score — never what the manifest or PDF list.
    """
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[f.rule_id].append(f)

    total = 0
    for rule_findings in groups.values():
        ranked = sorted(rule_findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
        for f in ranked[:_SCORE_CAP_PER_RULE]:
            total += _SEVERITY_POINTS.get(f.severity, 0)

    score = min(_MAX_SCORE, total)
    return ScoreResult(score=score, tier=_tier(score))
