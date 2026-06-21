from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_tool_audit.models import ToolDefinition


class ManifestError(ValueError):
    """Raised when a tool manifest cannot be normalized."""


def load_manifest(path: str | Path) -> list[ToolDefinition]:
    manifest_path = Path(path)
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ManifestError(f"cannot read {manifest_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(
            f"{manifest_path}:{exc.lineno}:{exc.colno}: invalid JSON: {exc.msg}"
        ) from exc

    entries = _extract_entries(payload)
    if not entries:
        raise ManifestError(f"{manifest_path}: manifest contains no tools")

    tools = [
        _normalize_tool(entry, source=str(manifest_path), index=index)
        for index, entry in enumerate(entries)
    ]
    return tools


def _extract_entries(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        raise ManifestError("manifest root must be an object or array")

    result = payload.get("result")
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        return result["tools"]
    if isinstance(payload.get("tools"), list):
        return payload["tools"]
    if _looks_like_tool(payload):
        return [payload]
    raise ManifestError("expected a tool object, a tools array, or an MCP tools/list result")


def _looks_like_tool(value: dict[str, Any]) -> bool:
    return isinstance(value.get("name"), str) or isinstance(value.get("function"), dict)


def _normalize_tool(entry: Any, *, source: str, index: int) -> ToolDefinition:
    if not isinstance(entry, dict):
        raise ManifestError(f"{source}: tool at index {index} must be an object")

    if isinstance(entry.get("function"), dict):
        function = entry["function"]
        return _build_tool(
            function,
            schema_key="parameters",
            source=source,
            dialect="openai",
            index=index,
        )
    if "input_schema" in entry:
        return _build_tool(
            entry,
            schema_key="input_schema",
            source=source,
            dialect="anthropic",
            index=index,
        )
    if "inputSchema" in entry:
        return _build_tool(
            entry,
            schema_key="inputSchema",
            source=source,
            dialect="mcp",
            index=index,
        )
    if "parameters" in entry:
        return _build_tool(
            entry,
            schema_key="parameters",
            source=source,
            dialect="function",
            index=index,
        )
    raise ManifestError(
        f"{source}: tool at index {index} has no parameters, input_schema, or inputSchema"
    )


def _build_tool(
    entry: dict[str, Any],
    *,
    schema_key: str,
    source: str,
    dialect: str,
    index: int,
) -> ToolDefinition:
    name = entry.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ManifestError(f"{source}: tool at index {index} has no valid name")

    description = entry.get("description", "")
    if description is None:
        description = ""
    if not isinstance(description, str):
        raise ManifestError(f"{source}: tool {name!r} has a non-string description")

    schema = entry.get(schema_key)
    if not isinstance(schema, dict):
        raise ManifestError(f"{source}: tool {name!r} has no valid input schema")

    return ToolDefinition(
        name=name.strip(),
        description=description.strip(),
        input_schema=schema,
        source=source,
        dialect=dialect,
    )

