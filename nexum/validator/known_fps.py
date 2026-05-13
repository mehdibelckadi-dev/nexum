"""Known false-positive database for the Nexum validator."""

from __future__ import annotations

import re
from typing import Any

KNOWN_FALSE_POSITIVES: list[dict[str, Any]] = [
    {
        "rule_id": "NEXUM-002",
        "match_field": "rule_name",
        "pattern": r"detach|disassociate|unlink|remove_support",
        "confidence_threshold": "MEDIUM",
        "description": "DELETE operations that detach resources rather than delete data",
    },
    {
        "rule_id": "NEXUM-003",
        "match_field": "path",
        "pattern": r".*/default$|.*/primary$",
        "confidence_threshold": "MEDIUM",
        "description": "Singleton endpoints by convention — already fixed in MOD-3",
    },
]

_CONFIDENCE_RANK: dict[str, int] = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _confidence_meets_threshold(confidence: str, threshold: str) -> bool:
    return _CONFIDENCE_RANK.get(confidence, 0) >= _CONFIDENCE_RANK.get(threshold, 0)


def match_false_positive(
    finding: dict[str, Any],
) -> tuple[dict[str, Any] | None, bool]:
    """Check finding against all known false-positive entries.

    Returns (matched_entry | None, incomplete_data).
    incomplete_data is True when the required match_field is absent in finding.
    """
    for entry in KNOWN_FALSE_POSITIVES:
        if entry["rule_id"] != finding.get("rule_id"):
            continue

        field = entry["match_field"]
        value = finding.get(field)

        if value is None:
            # Field absent in reconstructed finding — cannot evaluate
            return None, True

        confidence = finding.get("confidence", "HIGH")
        if not _confidence_meets_threshold(confidence, entry["confidence_threshold"]):
            continue

        if re.search(entry["pattern"], str(value)):
            return entry, False

    return None, False
