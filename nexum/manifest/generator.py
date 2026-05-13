"""Trust Manifest draft generator."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..core.rules.base import Finding
from ..core.scorer import ScoreResult

_REQUIRES_HUMAN_REVIEW = "REQUIRES_HUMAN_REVIEW"

_NUMERIC_CONSTRAINT_KEYS: frozenset[str] = frozenset({
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
    "minLength", "maxLength", "minItems", "maxItems",
})


# ---------------------------------------------------------------------------
# Invariant extractors
# ---------------------------------------------------------------------------

def _extract_required_headers(spec: dict[str, Any]) -> list[str]:
    headers: set[str] = set()
    for path_item in spec.get("paths", {}).values():
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            for param in operation.get("parameters", []):
                if (
                    isinstance(param, dict)
                    and param.get("in") == "header"
                    and param.get("required")
                ):
                    headers.add(param["name"])
    return sorted(headers)


def _extract_immutable_fields(spec: dict[str, Any]) -> list[str]:
    fields: set[str] = set()
    for schema in spec.get("components", {}).get("schemas", {}).values():
        if not isinstance(schema, dict):
            continue
        for prop_name, prop in schema.get("properties", {}).items():
            if isinstance(prop, dict) and prop.get("readOnly"):
                fields.add(prop_name)
    return sorted(fields)


def _extract_numeric_limits(spec: dict[str, Any]) -> dict[str, Any]:
    limits: dict[str, Any] = {}
    for schema_name, schema in spec.get("components", {}).get("schemas", {}).items():
        if not isinstance(schema, dict):
            continue
        for prop_name, prop in schema.get("properties", {}).items():
            if not isinstance(prop, dict):
                continue
            constraints = {k: prop[k] for k in _NUMERIC_CONSTRAINT_KEYS if k in prop}
            if constraints:
                limits[f"{schema_name}.{prop_name}"] = constraints
    return limits


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate(
    findings: list[Finding],
    result: ScoreResult,
    source_file: str,
    spec: dict[str, Any],
) -> dict[str, Any]:
    """Build a Trust Manifest draft dict.

    Fields that cannot be reliably inferred from the spec are set to
    REQUIRES_HUMAN_REVIEW and listed in manual_review_required.
    """
    req_headers = _extract_required_headers(spec)
    imm_fields = _extract_immutable_fields(spec)
    num_limits = _extract_numeric_limits(spec)

    manual_review: list[dict[str, str]] = [
        {
            "field": "model_compatibility_range",
            "reason": (
                "Cannot be inferred from the spec. Depends on model capabilities, "
                "deployment context, and the desired trust level for this integration."
            ),
        }
    ]
    if not imm_fields:
        manual_review.append({
            "field": "auto_detected_invariants.immutable_fields",
            "reason": (
                "No readOnly properties found in component schemas. "
                "Manually list any fields that must never change after resource creation."
            ),
        })
    if not num_limits:
        manual_review.append({
            "field": "auto_detected_invariants.numeric_limits",
            "reason": (
                "No numeric or length constraints found in component schemas. "
                "Specify min/max bounds for any safety-critical numeric fields."
            ),
        })

    return {
        "manifest_version": "1.0-draft",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "source_file": source_file,
        "inferred_risk_tier": result.tier,
        "nexum_risk_score": result.score,
        "model_compatibility_range": _REQUIRES_HUMAN_REVIEW,
        "auto_detected_invariants": {
            "immutable_fields": imm_fields,
            "numeric_limits": num_limits,
            "required_headers": req_headers,
        },
        "findings_summary": [
            {
                "rule_id":           f.rule_id,
                "rule_name":         f.rule_name,
                "severity":          f.severity,
                "path":              f.path,
                "method":            f.method,
                "confidence":        f.confidence,
                "confidence_reason": f.confidence_reason,
            }
            for f in findings
        ],
        "manual_review_required": manual_review,
    }
