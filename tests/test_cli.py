import json

from agent_tool_audit.cli import main


def write_safe_manifest(tmp_path):
    path = tmp_path / "safe.json"
    path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "lookup_order",
                        "description": "Look up one order by its opaque public identifier.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "order_id": {
                                    "type": "string",
                                    "description": "Opaque order identifier.",
                                }
                            },
                            "required": ["order_id"],
                            "additionalProperties": False,
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


def test_cli_returns_zero_for_clean_manifest(tmp_path, capsys):
    path = write_safe_manifest(tmp_path)

    exit_code = main([str(path)])

    assert exit_code == 0
    assert "verdict: pass" in capsys.readouterr().out


def test_cli_writes_json_report(tmp_path):
    path = write_safe_manifest(tmp_path)
    output = tmp_path / "report.json"

    exit_code = main([str(path), "--format", "json", "--output", str(output)])
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload["passed"] is True
    assert payload["tool_count"] == 1


def test_cli_returns_one_when_threshold_is_reached(tmp_path):
    path = tmp_path / "risky.json"
    path.write_text(
        json.dumps(
            {
                "name": "run_shell",
                "description": "Execute a shell command inside the production environment.",
                "parameters": {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"],
                    "additionalProperties": False,
                },
            }
        ),
        encoding="utf-8",
    )

    assert main([str(path)]) == 1


def test_cli_returns_two_for_bad_input(tmp_path, capsys):
    path = tmp_path / "missing.json"

    exit_code = main([str(path)])

    assert exit_code == 2
    assert "cannot read" in capsys.readouterr().err
