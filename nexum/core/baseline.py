"""Baseline / suppression mechanism.

Lets a team consciously accept known findings and exclude them from the score on
later scans. Suppression is matched by a deterministic per-finding hash, so the
same finding on the same spec always resolves to the same baseline entry.

This is a pure filtering layer over already-computed findings: it never mutates
the Finding dataclass, the rules, or the scorer. The score is recomputed on the
active (non-suppressed) findings, not adjusted after the fact.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .rules.base import Finding

BASELINE_VERSION = "1.0"

# Fields every baseline entry must carry. The hash is the source of truth for
# matching; rule_id/path/method are human-readable context for review.
_REQUIRED_ENTRY_FIELDS = ("hash", "rule_id", "path", "method")


class BaselineError(Exception):
    """Raised when a baseline file is malformed or has an invalid schema."""


def _utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string with a trailing 'Z'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def finding_hash(finding: Finding) -> str:
    """Deterministic hash for a finding. Rule + path + method + severity.

    Does NOT include evidence_snippet (can change with spec formatting) or
    human_explanation (can change with Nexum versions). Stable across scans of
    the same spec.
    """
    canonical = json.dumps(
        {
            "rule_id": finding.rule_id,
            "path": finding.path,
            "method": finding.method,
            "severity": finding.severity,
        },
        sort_keys=True,
    )
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()[:16]


def load_baseline(path: Path) -> dict:
    """Load and validate a .nexumbaseline.json file.

    Raises BaselineError on any schema problem so failures are explicit, never
    silent.
    """
    try:
        raw = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"could not read baseline file: {exc}") from exc

    if not isinstance(raw, dict):
        raise BaselineError("baseline root must be a JSON object")
    if "version" not in raw:
        raise BaselineError("baseline missing required field 'version'")
    entries = raw.get("entries")
    if not isinstance(entries, list):
        raise BaselineError("baseline field 'entries' must be a list")
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise BaselineError(f"baseline entry {i} must be an object")
        for field in _REQUIRED_ENTRY_FIELDS:
            if not isinstance(entry.get(field), str):
                raise BaselineError(
                    f"baseline entry {i} missing/invalid string field '{field}'"
                )
    return raw


def filter_baseline(
    findings: list[Finding], baseline: dict
) -> tuple[list[Finding], list[Finding]]:
    """Split findings into (active, suppressed) using the baseline's hashes."""
    suppressed_hashes = {e["hash"] for e in baseline["entries"]}
    active: list[Finding] = []
    suppressed: list[Finding] = []
    for f in findings:
        if finding_hash(f) in suppressed_hashes:
            suppressed.append(f)
        else:
            active.append(f)
    return active, suppressed


def generate_baseline(findings: list[Finding], output_path: Path) -> None:
    """Write a .nexumbaseline.json accepting every current finding for review."""
    now = _utc_now_iso()
    entries = [
        {
            "hash": finding_hash(f),
            "rule_id": f.rule_id,
            "path": f.path,
            "method": f.method,
            "accepted_by": "human-review",
            "accepted_at": now,
            "reason": "",
        }
        for f in findings
    ]
    document = {
        "version": BASELINE_VERSION,
        "created_at": now,
        "entries": entries,
    }
    Path(output_path).write_text(json.dumps(document, indent=2) + "\n")
