from __future__ import annotations

from collections import Counter

from agent_tool_audit.capabilities import Capability, classify
from agent_tool_audit.models import AuditReport, Finding, Severity, ToolDefinition
from agent_tool_audit.rules import audit_tool


def audit_tools(
    tools: list[ToolDefinition], *, ignored_rules: set[str] | None = None
) -> AuditReport:
    ignored = ignored_rules or set()
    findings: list[Finding] = []

    counts = Counter(tool.name for tool in tools)
    for name, count in counts.items():
        if count > 1:
            findings.append(
                Finding(
                    rule_id="ATA002",
                    severity=Severity.ERROR,
                    message=f"tool name is defined {count} times",
                    tool=name,
                    remediation="give every exposed tool a unique name",
                )
            )

    for tool in tools:
        findings.extend(audit_tool(tool))
    findings.extend(_combination_findings(tools))

    filtered = [finding for finding in findings if finding.rule_id not in ignored]
    filtered.sort(key=lambda item: (-item.severity.rank, item.rule_id, item.tool, item.path))
    return AuditReport(tools=tools, findings=filtered)


def _combination_findings(tools: list[ToolDefinition]) -> list[Finding]:
    by_capability: dict[Capability, list[str]] = {capability: [] for capability in Capability}
    for tool in tools:
        for capability in classify(tool):
            by_capability[capability].append(tool.name)

    findings: list[Finding] = []
    findings.extend(
        _capability_pair(
            by_capability,
            left=Capability.SECRET_ACCESS,
            right=Capability.NETWORK_SEND,
            rule_id="ATA301",
            severity=Severity.CRITICAL,
            message="toolset combines secret access with outbound data transfer",
            remediation="separate these capabilities or enforce a destination and data-flow policy",
        )
    )
    findings.extend(
        _capability_pair(
            by_capability,
            left=Capability.FILE_READ,
            right=Capability.NETWORK_SEND,
            rule_id="ATA302",
            severity=Severity.ERROR,
            message="toolset creates a file-exfiltration path",
            remediation=(
                "restrict readable paths and outbound destinations, then require user approval"
            ),
        )
    )
    findings.extend(
        _capability_pair(
            by_capability,
            left=Capability.CODE_EXECUTION,
            right=Capability.SECRET_ACCESS,
            rule_id="ATA303",
            severity=Severity.CRITICAL,
            message="toolset combines arbitrary execution with secret access",
            remediation="remove raw secret access from the execution environment",
        )
    )
    return findings


def _capability_pair(
    by_capability: dict[Capability, list[str]],
    *,
    left: Capability,
    right: Capability,
    rule_id: str,
    severity: Severity,
    message: str,
    remediation: str,
) -> list[Finding]:
    left_tools = by_capability[left]
    right_tools = by_capability[right]
    if not left_tools or not right_tools:
        return []
    names = sorted(set(left_tools + right_tools))
    return [
        Finding(
            rule_id=rule_id,
            severity=severity,
            message=message,
            tool=" + ".join(names),
            evidence=(
                f"{left.value}: {', '.join(left_tools)}; "
                f"{right.value}: {', '.join(right_tools)}"
            ),
            remediation=remediation,
        )
    ]
