from agent_tool_audit.analyzer import audit_tools
from agent_tool_audit.models import Severity, ToolDefinition


def tool(name, description, properties, required=None, additional_properties=False):
    return ToolDefinition(
        name=name,
        description=description,
        input_schema={
            "type": "object",
            "properties": properties,
            "required": required or [],
            "additionalProperties": additional_properties,
        },
        source="test.json",
        dialect="test",
    )


def rule_ids(report):
    return {finding.rule_id for finding in report.findings}


def test_clean_narrow_tool_passes():
    candidate = tool(
        "lookup_order",
        "Look up one order by its opaque public identifier.",
        {
            "order_id": {
                "type": "string",
                "description": "Opaque order identifier shown to the customer.",
            }
        },
        required=["order_id"],
    )

    report = audit_tools([candidate])

    assert report.findings == []
    assert not report.fails_at(Severity.WARNING)


def test_flags_arbitrary_shell_execution():
    candidate = tool(
        "run_shell",
        "Execute a shell command inside the application environment.",
        {"command": {"type": "string"}},
        required=["command"],
    )

    report = audit_tools([candidate])

    assert {"ATA103", "ATA104", "ATA201"}.issubset(rule_ids(report))
    assert report.findings[0].severity is Severity.CRITICAL


def test_flags_destructive_tool_without_confirmation():
    candidate = tool(
        "delete_account",
        "Permanently delete a customer account and its stored data.",
        {
            "user_id": {
                "type": "string",
                "description": "Stable identifier of the account owner.",
            }
        },
        required=["user_id"],
    )

    assert "ATA203" in rule_ids(audit_tools([candidate]))


def test_detects_secret_exfiltration_capability_pair():
    secret_tool = tool(
        "read_secret",
        "Read a credential from the protected environment variable store.",
        {
            "secret_name": {
                "type": "string",
                "description": "Approved credential alias.",
                "enum": ["SUPPORT_TOKEN"],
            }
        },
        required=["secret_name"],
    )
    webhook_tool = tool(
        "send_webhook",
        "Send a webhook payload to the approved incident endpoint.",
        {
            "url": {
                "type": "string",
                "description": "Approved incident receiver.",
                "const": "https://hooks.example.test/incidents",
            },
            "payload": {"type": "object"},
        },
        required=["url", "payload"],
    )

    report = audit_tools([secret_tool, webhook_tool])

    assert "ATA301" in rule_ids(report)


def test_detects_duplicate_tool_names():
    first = tool("search", "Search the public product documentation index.", {}, [])
    second = tool("search", "Search the internal support documentation index.", {}, [])

    assert "ATA002" in rule_ids(audit_tools([first, second]))


def test_ignored_rule_is_removed():
    candidate = tool(
        "run_shell",
        "Execute a shell command inside an isolated disposable sandbox.",
        {
            "command": {
                "type": "string",
                "description": "Command selected by the sandbox controller.",
            }
        },
        required=["command"],
    )

    report = audit_tools([candidate], ignored_rules={"ATA201", "ATA104"})

    assert "ATA201" not in rule_ids(report)
    assert "ATA104" not in rule_ids(report)

