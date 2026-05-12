"""NEXUM-003 — UnboundedScope: wildcard params or DELETE/PATCH without mandatory filters."""

from __future__ import annotations

import json
import re
from typing import Any

from .base import BaseRule, Finding

_SCOPED_METHODS: frozenset[str] = frozenset({"DELETE", "PATCH"})
_WILDCARD_RE = re.compile(r"^\*$|^\.\*$|^%$")
_SINGLETON_TERMINAL_SEGMENTS: frozenset[str] = frozenset({"default", "primary"})


def _path_is_singleton(path: str) -> bool:
    segment = path.rstrip("/").rsplit("/", 1)[-1]
    return segment in _SINGLETON_TERMINAL_SEGMENTS


def _path_has_param(path: str) -> bool:
    return bool(re.search(r"\{[^}]+\}", path))


def _has_required_query_filter(operation: dict[str, Any]) -> bool:
    return any(
        isinstance(p, dict) and p.get("in") == "query" and p.get("required")
        for p in operation.get("parameters", [])
    )


def _wildcard_param(operation: dict[str, Any]) -> dict[str, Any] | None:
    """Return the first parameter whose schema contains a wildcard default or enum value."""
    for param in operation.get("parameters", []):
        if not isinstance(param, dict):
            continue
        schema = param.get("schema", {})
        if not isinstance(schema, dict):
            continue
        if _WILDCARD_RE.match(str(schema.get("default", ""))):
            return param
        if any(_WILDCARD_RE.match(str(v)) for v in schema.get("enum", [])):
            return param
    return None


class UnboundedScope(BaseRule):
    """Flags DELETE/PATCH operations that can affect an unbounded set of resources."""

    RULE_ID = "NEXUM-003"
    RULE_NAME = "UnboundedScope"
    SEVERITY = "HIGH"

    def check(self, spec: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        for path, path_item in spec.get("paths", {}).items():
            for method, operation in path_item.items():
                if not isinstance(operation, dict):
                    continue
                if method.upper() not in _SCOPED_METHODS:
                    continue

                if _path_is_singleton(path):
                    continue

                bad_param = _wildcard_param(operation)
                if bad_param:
                    findings.append(self._finding(
                        path, method, operation,
                        trigger="wildcard_param",
                        trigger_detail=bad_param,
                        explanation=(
                            f"{method.upper()} {path}: parameter '{bad_param.get('name')}' "
                            "accepts a wildcard value that could match an unbounded set of resources."
                        ),
                    ))
                    continue  # wildcard already covers the worst case for this operation

                if not _path_has_param(path) and not _has_required_query_filter(operation):
                    findings.append(self._finding(
                        path, method, operation,
                        trigger="no_filter",
                        trigger_detail={"parameters": operation.get("parameters", [])},
                        explanation=(
                            f"{method.upper()} {path} has no path parameter and no required "
                            "query filter — the operation may affect every resource in the collection."
                        ),
                    ))

        return findings

    def _finding(
        self,
        path: str,
        method: str,
        operation: dict[str, Any],
        trigger: str,
        trigger_detail: Any,
        explanation: str,
    ) -> Finding:
        snippet = {
            "path": path,
            "method": method.upper(),
            "trigger": trigger,
            "detail": trigger_detail,
        }
        return Finding(
            rule_id=self.RULE_ID,
            rule_name=self.RULE_NAME,
            severity=self.SEVERITY,
            path=path,
            method=method.upper(),
            evidence_snippet=json.dumps(snippet, indent=2),
            human_explanation=explanation,
            guardrail_suggestion=(
                "Require either a path parameter that identifies an individual resource "
                "(e.g. /{resource_id}) or at least one mandatory query filter before "
                "executing DELETE or PATCH. Reject requests that would affect more "
                "resources than the caller explicitly named."
            ),
        )
