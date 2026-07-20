"""SARIF 2.1.0 formatter — a pure presentation view over already-computed findings.

This module performs no risk logic: it maps existing ``Finding`` objects onto the
SARIF 2.1.0 schema used by CodeQL, Semgrep, Trivy and GitHub Code Scanning. The
deterministic core (rules, scorer, manifest) is never consulted or mutated here.
"""

from __future__ import annotations

from ..engine import _RULES
from ..rules.base import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

# Nexum severity → SARIF result level. Unknown severities fall back to "none".
_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH": "warning",
    "MEDIUM": "note",
    "LOW": "none",
}

# Short, human-readable descriptions per rule. Kept here (not on the rule classes)
# so the deterministic core stays untouched; keyed by rule id.
_SHORT_DESCRIPTIONS = {
    "NEXUM-001": "Credentials transmitted via query string",
    "NEXUM-002": "Deletion with no specific resource identifier",
    "NEXUM-003": "Wildcard params, or DELETE/PATCH with no required filter",
    "NEXUM-004": "Mutation with no Idempotency-Key header",
    "NEXUM-005": "additionalProperties: true on a mutation schema",
}

_HELP_URI_BASE = "https://getnexum.dev/docs#"
_INFORMATION_URI = "https://getnexum.dev"


def _build_rules() -> list[dict]:
    """Build the SARIF driver.rules array from the live engine rule set."""
    rules = []
    for rule in _RULES:
        rule_id = rule.RULE_ID
        rules.append(
            {
                "id": rule_id,
                "name": rule.RULE_NAME,
                "shortDescription": {"text": _SHORT_DESCRIPTIONS.get(rule_id, rule.RULE_NAME)},
                "helpUri": f"{_HELP_URI_BASE}{rule_id.lower()}",
                "properties": {"tags": ["security", "agentic-risk"]},
            }
        )
    return rules


def _build_result(finding: Finding, source_file: str) -> dict:
    """Map a single Finding onto a SARIF result object."""
    return {
        "ruleId": finding.rule_id,
        "level": _LEVEL_MAP.get(finding.severity, "none"),
        "message": {"text": finding.human_explanation},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": source_file},
                    "region": {
                        # TD: region.startLine is fixed at 1 — no line number available from
                        # deterministic spec analysis. To fix: parse the raw spec YAML/JSON to
                        # find the byte offset of the path+method combination and map to line number.
                        # Deferred — requires changes to ingestor.py to track source positions.
                        "startLine": 1,
                        "snippet": {"text": finding.evidence_snippet},
                    },
                },
                "logicalLocations": [
                    {
                        "name": finding.path,
                        "kind": "function",
                        "decoratedName": f"{finding.method} {finding.path}",
                    }
                ],
            }
        ],
    }


def to_sarif(findings: list[Finding], source_file: str, version: str = "0.1.0") -> dict:
    """Convert Nexum findings to SARIF 2.1.0 format."""
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Nexum",
                        "version": version,
                        "informationUri": _INFORMATION_URI,
                        "rules": _build_rules(),
                    }
                },
                "results": [_build_result(f, source_file) for f in findings],
                "artifacts": [
                    {
                        "location": {"uri": source_file},
                        "mimeType": "application/json",
                    }
                ],
            }
        ],
    }
