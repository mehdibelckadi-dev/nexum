"""Internal scan telemetry — frictionless logging of every /scan and /report request.

This only records what the request already carries (spec hash, timestamp,
client IP): free-tier usage was previously invisible. Independent from the
CLI's own findings_log.jsonl usage, though it shares the same default path
and gitignore entry when no volume is configured.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

_DEFAULT_LOG_PATH = Path(__file__).resolve().parent.parent / "nexum" / "data" / "findings_log.jsonl"


def _log_path() -> Path:
    configured = os.environ.get("NEXUM_SCAN_LOG_PATH")
    return Path(configured) if configured else _DEFAULT_LOG_PATH


def log_scan_event(
    *,
    endpoint: str,
    filename: str,
    content: bytes,
    client_ip: str | None,
    findings_count: int,
    score: int,
    tier: int,
    email_requested: bool = False,
) -> None:
    """Append one JSONL record. Never raises — a logging failure must not break a scan."""
    event = {
        "scan_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "endpoint": endpoint,
        "filename": filename,
        "spec_sha256": hashlib.sha256(content).hexdigest(),
        "client_ip": client_ip or "unknown",
        "findings_count": findings_count,
        "score": score,
        "tier": tier,
        "email_requested": email_requested,
    }
    path = _log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except OSError as exc:
        print(f"[nexum] scan log write failed: {exc}")
