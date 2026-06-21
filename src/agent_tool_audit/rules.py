from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from agent_tool_audit.capabilities import Capability, classify
from agent_tool_audit.models import Finding, Severity, ToolDefinition

_COMMAND_FIELDS = {"command", "cmd", "code", "script", "shell"}
_DESTINATION_FIELDS = {"url", "uri", "endpoint", "webhook", "host", "recipient", "email"}
_ACTION_FIELDS = {"action", "operation", "method"}
_HIGH_IMPACT_FIELDS = (
    _COMMAND_FIELDS
    | _DESTINATION_FIELDS
    | _ACTION_FIELDS
    | {"path", "file_path", "amount", "secret", "secret_name", "token", "user_id", "role"}
)
_CONFIRMATION_FIELDS = {"confirm", "confirmation", "approved", "dry_run"}
_IDEMPOTENCY_FIELDS = {"idempotency_key", "request_id", "operation_id"}


@dataclass(frozen=True, slots=True)
class SchemaProperty:
    name: str
    schema: dict[str, Any]
    path: str
    required: bool


def audit_tool(tool: ToolDefinition) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_description_findings(tool))
    findings.extend(_schema_findings(tool))
    findings.extend(_capability_findings(tool))
    return findings


def _description_findings(tool: ToolDefinition) -> list[Finding]:
    if not tool.description:
        return [
            Finding(
                rule_id="ATA001",
                severity=Severity.ERROR,
                message="tool has no description, so the model cannot judge its intended boundary",
                tool=tool.name,
                path="description",
                remediation=(
                    "describe the allowed action, constraints, and cases where the tool must not "
                    "be used"
                ),
            )
        ]
    if len(tool.description) < 24:
        return [
            Finding(
                rule_id="ATA001",
                severity=Severity.WARNING,
                message="tool description is too short to communicate a useful safety boundary",
                tool=tool.name,
                path="description",
                evidence=tool.description,
                remediation="state the tool's purpose and important restrictions",
            )
        ]
    return []


def _schema_findings(tool: ToolDefinition) -> list[Finding]:
    schema = tool.input_schema
    findings: list[Finding] = []
    if schema.get("type") != "object":
        findings.append(
            Finding(
                rule_id="ATA101",
                severity=Severity.ERROR,
                message="input schema root is not explicitly an object",
                tool=tool.name,
                path="input_schema.type",
                evidence=repr(schema.get("type")),
                remediation='set the root schema to {"type": "object"}',
            )
        )

    properties = schema.get("properties")
    if not isinstance(properties, dict) or not properties:
        findings.append(
            Finding(
                rule_id="ATA101",
                severity=Severity.WARNING,
                message="input schema defines no named properties",
                tool=tool.name,
                path="input_schema.properties",
                remediation="define the smallest explicit set of arguments the tool accepts",
            )
        )

    if schema.get("additionalProperties") is not False:
        findings.append(
            Finding(
                rule_id="ATA102",
                severity=Severity.WARNING,
                message="input schema permits undeclared arguments",
                tool=tool.name,
                path="input_schema.additionalProperties",
                remediation="set additionalProperties to false",
            )
        )

    for prop in _walk_properties(schema):
        findings.extend(_property_findings(tool, prop))
    return findings


def _property_findings(tool: ToolDefinition, prop: SchemaProperty) -> list[Finding]:
    findings: list[Finding] = []
    name = prop.name.lower()
    schema = prop.schema
    constraints = {"enum", "const", "pattern", "format", "maxLength"}

    if name in _HIGH_IMPACT_FIELDS and not schema.get("description"):
        findings.append(
            Finding(
                rule_id="ATA103",
                severity=Severity.WARNING,
                message=f"high-impact parameter {prop.name!r} has no description",
                tool=tool.name,
                path=prop.path,
                remediation="document accepted values and the parameter's safety constraints",
            )
        )

    if name in _COMMAND_FIELDS and not constraints.intersection(schema):
        findings.append(
            Finding(
                rule_id="ATA104",
                severity=Severity.ERROR,
                message=f"command-like parameter {prop.name!r} accepts unrestricted text",
                tool=tool.name,
                path=prop.path,
                remediation=(
                    "replace free-form commands with a constrained operation enum and typed "
                    "arguments"
                ),
            )
        )

    if name in _DESTINATION_FIELDS and not constraints.intersection(schema):
        findings.append(
            Finding(
                rule_id="ATA105",
                severity=Severity.ERROR,
                message=f"destination parameter {prop.name!r} has no allowlist-style constraint",
                tool=tool.name,
                path=prop.path,
                remediation="use an enum, const, hostname pattern, or validated format",
            )
        )

    if name in _ACTION_FIELDS and not {"enum", "const"}.intersection(schema):
        findings.append(
            Finding(
                rule_id="ATA106",
                severity=Severity.ERROR,
                message=f"action selector {prop.name!r} is not limited to known operations",
                tool=tool.name,
                path=prop.path,
                remediation="define an enum containing only supported operations",
            )
        )

    if name in _HIGH_IMPACT_FIELDS and not prop.required:
        findings.append(
            Finding(
                rule_id="ATA107",
                severity=Severity.WARNING,
                message=f"high-impact parameter {prop.name!r} is optional",
                tool=tool.name,
                path=prop.path,
                remediation="make the parameter required or define a safe explicit default",
            )
        )
    return findings


def _capability_findings(tool: ToolDefinition) -> list[Finding]:
    capabilities = classify(tool)
    property_names = {prop.name.lower() for prop in _walk_properties(tool.input_schema)}
    findings: list[Finding] = []

    if Capability.CODE_EXECUTION in capabilities:
        findings.append(
            Finding(
                rule_id="ATA201",
                severity=Severity.CRITICAL,
                message="tool exposes code or shell execution to the model",
                tool=tool.name,
                remediation=(
                    "replace arbitrary execution with narrow, named operations or isolate it in "
                    "a sandbox"
                ),
            )
        )
    if Capability.SECRET_ACCESS in capabilities:
        findings.append(
            Finding(
                rule_id="ATA202",
                severity=Severity.WARNING,
                message="tool can access secrets or credentials",
                tool=tool.name,
                remediation=(
                    "return scoped handles where possible and never expose raw secret values"
                ),
            )
        )
    if Capability.DESTRUCTIVE in capabilities and not property_names.intersection(
        _CONFIRMATION_FIELDS
    ):
        findings.append(
            Finding(
                rule_id="ATA203",
                severity=Severity.ERROR,
                message="destructive tool has no explicit confirmation or dry-run argument",
                tool=tool.name,
                remediation="add a required confirmation token or a safe dry-run mode",
            )
        )
    if Capability.FINANCIAL_MUTATION in capabilities:
        missing = []
        if not property_names.intersection(_CONFIRMATION_FIELDS):
            missing.append("confirmation")
        if not property_names.intersection(_IDEMPOTENCY_FIELDS):
            missing.append("idempotency key")
        if missing:
            findings.append(
                Finding(
                    rule_id="ATA204",
                    severity=Severity.ERROR,
                    message=f"financial mutation is missing {' and '.join(missing)}",
                    tool=tool.name,
                    remediation="require explicit approval and an idempotency key",
                )
            )
    return findings


def _walk_properties(
    schema: dict[str, Any], *, prefix: str = "input_schema.properties"
) -> Iterator[SchemaProperty]:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return
    required_values = schema.get("required", [])
    required = set(required_values) if isinstance(required_values, list) else set()

    for name, value in properties.items():
        if not isinstance(name, str) or not isinstance(value, dict):
            continue
        path = f"{prefix}.{name}"
        yield SchemaProperty(name=name, schema=value, path=path, required=name in required)
        yield from _walk_properties(value, prefix=f"{path}.properties")
