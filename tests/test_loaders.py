import json

import pytest

from agent_tool_audit.loaders import ManifestError, load_manifest


def write_manifest(tmp_path, payload):
    path = tmp_path / "tools.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_loads_openai_function_tools(tmp_path):
    path = write_manifest(
        tmp_path,
        {
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "lookup_order",
                        "description": "Look up one order by its public order identifier.",
                        "parameters": {
                            "type": "object",
                            "properties": {"order_id": {"type": "string"}},
                        },
                    },
                }
            ]
        },
    )

    tools = load_manifest(path)

    assert tools[0].name == "lookup_order"
    assert tools[0].dialect == "openai"


def test_loads_anthropic_tools(tmp_path):
    path = write_manifest(
        tmp_path,
        [
            {
                "name": "search_docs",
                "description": "Search the approved internal documentation collection.",
                "input_schema": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                },
            }
        ],
    )

    assert load_manifest(path)[0].dialect == "anthropic"


def test_loads_mcp_tools_list_result(tmp_path):
    path = write_manifest(
        tmp_path,
        {
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {
                        "name": "create_note",
                        "description": "Create a note in the current support ticket.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"body": {"type": "string"}},
                        },
                    }
                ]
            },
        },
    )

    assert load_manifest(path)[0].dialect == "mcp"


def test_rejects_manifest_without_tools(tmp_path):
    path = write_manifest(tmp_path, {"name": "not-enough"})

    with pytest.raises(ManifestError, match="has no parameters"):
        load_manifest(path)


def test_rejects_invalid_json(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{", encoding="utf-8")

    with pytest.raises(ManifestError, match="invalid JSON"):
        load_manifest(path)
