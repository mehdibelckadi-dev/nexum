"""PACT-001 — AuthLeakageRisk: credentials transmitted via query string."""

from __future__ import annotations

import json
from typing import Any

from .base import BaseRule, Finding

# Names that strongly indicate a credential or secret value.
# Normalised to lower-case with hyphens replaced by underscores before matching.
_SENSITIVE_NAMES: frozenset[str] = frozenset({
    "api_key", "apikey", "api_secret",
    "token", "access_token", "auth_token", "id_token", "refresh_token",
    "bearer",
    "secret", "client_secret",
    "password", "passwd", "pass",
    "key", "private_key",
    "authorization", "auth",
    "credential", "credentials",
    "session", "session_id", "session_key",
    "x_api_key",
})


def _normalise_name(raw: str) -> str:
    return raw.lower().replace("-", "_")


class AuthLeakageRisk(BaseRule):
    """Flags any operation that accepts a credential-like parameter via query string."""

    RULE_ID = "PACT-001"
    RULE_NAME = "AuthLeakageRisk"
    SEVERITY = "CRITICAL"

    def check(self, spec: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        for path, path_item in spec.get("paths", {}).items():
            for method, operation in path_item.items():
                if not isinstance(operation, dict):
                    continue

                for param in operation.get("parameters", []):
                    if not isinstance(param, dict):
                        continue
                    if param.get("in") != "query":
                        continue

                    raw_name: str = param.get("name", "")
                    if _normalise_name(raw_name) not in _SENSITIVE_NAMES:
                        continue

                    findings.append(Finding(
                        rule_id=self.RULE_ID,
                        rule_name=self.RULE_NAME,
                        severity=self.SEVERITY,
                        path=path,
                        method=method.upper(),
                        evidence_snippet=json.dumps(param, indent=2),
                        human_explanation=(
                            f"Parameter '{raw_name}' is transmitted in the query string. "
                            "Query parameters appear in server access logs, browser history, "
                            "proxy logs, and Referer headers, exposing the credential to "
                            "unintended parties without any additional attack surface."
                        ),
                        guardrail_suggestion=(
                            "Move the credential to the Authorization header "
                            "(e.g. 'Authorization: Bearer <token>') or to a request body "
                            "sent over TLS. Never embed secrets in URLs."
                        ),
                    ))

        return findings
