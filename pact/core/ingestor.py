"""Ingests MCP or OpenAPI spec files and returns a normalised structure."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


class PactIngestError(Exception):
    """Raised when a spec file cannot be parsed or its format is not recognised."""


def _load_raw(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()

    if suffix == ".json":
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise PactIngestError(f"Invalid JSON in '{path}': {exc}") from exc

    if suffix in {".yaml", ".yml"}:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PactIngestError(f"Invalid YAML in '{path}': {exc}") from exc
        if not isinstance(data, dict):
            raise PactIngestError(
                f"Expected a YAML mapping at the top level in '{path}', "
                f"got {type(data).__name__}."
            )
        return data

    # Unknown extension — probe JSON then YAML
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            return data
    except yaml.YAMLError:
        pass
    raise PactIngestError(
        f"Cannot parse '{path}': extension '{suffix}' is not recognised "
        "and content is neither valid JSON nor YAML."
    )


def _is_openapi(raw: dict[str, Any]) -> bool:
    return "openapi" in raw or "swagger" in raw


def _is_mcp(raw: dict[str, Any]) -> bool:
    return "tools" in raw and isinstance(raw["tools"], list)


def _normalize_openapi(raw: dict[str, Any]) -> dict[str, Any]:
    # Swagger 2.0 stores schemas under 'definitions'; OpenAPI 3.x uses 'components'
    components = raw.get("components") or {}
    if not components and "definitions" in raw:
        components = {"schemas": raw["definitions"]}

    return {
        "info": raw.get("info", {}),
        "paths": raw.get("paths", {}),
        "components": components,
        "_source_format": "openapi",
    }


def _normalize_mcp(raw: dict[str, Any]) -> dict[str, Any]:
    """Convert an MCP tool list into an OpenAPI-compatible normalised structure.

    Each tool is mapped to POST /tools/{tool_name} so that the rule engine can
    treat MCP and OpenAPI specs uniformly.
    """
    paths: dict[str, Any] = {}
    schemas: dict[str, Any] = {}

    for tool in raw.get("tools", []):
        name: str = tool.get("name", "unknown")
        input_schema: dict[str, Any] = tool.get("inputSchema", {})

        paths[f"/tools/{name}"] = {
            "post": {
                "operationId": name,
                "description": tool.get("description", ""),
                "parameters": [],
                "requestBody": {
                    "content": {
                        "application/json": {"schema": input_schema}
                    }
                },
                "x-mcp-tool": True,
            }
        }

        if input_schema:
            schemas[name] = input_schema

    return {
        "info": {
            "title": raw.get("name", "MCP Server"),
            "version": raw.get("mcp_version", "1.0"),
        },
        "paths": paths,
        "components": {"schemas": schemas},
        "_source_format": "mcp",
    }


def ingest(file_path: str | Path) -> dict[str, Any]:
    """Parse an MCP or OpenAPI spec file and return a normalised dict.

    The returned dict always contains the keys:
        info        — API / server metadata
        paths       — mapping of path -> {method -> operation}
        components  — schemas and security definitions
        _source_format — "openapi" | "mcp"

    Raises:
        PactIngestError: if the file is missing, unparseable, or of unknown format.
    """
    path = Path(file_path)

    if not path.exists():
        raise PactIngestError(f"File not found: '{path}'")

    raw = _load_raw(path)

    if _is_openapi(raw):
        return _normalize_openapi(raw)

    if _is_mcp(raw):
        return _normalize_mcp(raw)

    raise PactIngestError(
        f"Unrecognised spec format in '{path}': expected an OpenAPI document "
        "(containing an 'openapi' key) or an MCP tool definition "
        "(containing a 'tools' list)."
    )
