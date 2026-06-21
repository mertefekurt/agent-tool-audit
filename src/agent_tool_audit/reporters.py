from __future__ import annotations

import json
from typing import Any

from agent_tool_audit.models import AuditReport, Severity


def render_terminal(report: AuditReport, *, threshold: Severity | None) -> str:
    counts = report.counts()
    lines = [f"agent-tool-audit · {len(report.tools)} tool(s)"]
    dialects = ", ".join(sorted({tool.dialect for tool in report.tools}))
    lines.append(f"dialects: {dialects}")
    lines.append("")

    if report.findings:
        for finding in report.findings:
            location = f" · {finding.path}" if finding.path else ""
            lines.append(
                f"{finding.severity.value.upper():8} {finding.rule_id} "
                f"[{finding.tool}]{location}"
            )
            lines.append(f"         {finding.message}")
            if finding.remediation:
                lines.append(f"         fix: {finding.remediation}")
            lines.append("")
    else:
        lines.extend(["PASS     no findings", ""])

    summary = " · ".join(
        f"{counts[severity.value]} {severity.value}"
        for severity in (Severity.CRITICAL, Severity.ERROR, Severity.WARNING, Severity.INFO)
    )
    verdict = "fail" if report.fails_at(threshold) else "pass"
    threshold_label = threshold.value if threshold else "none"
    lines.append(summary)
    lines.append(f"verdict: {verdict} (threshold: {threshold_label})")
    return "\n".join(lines)


def render_json(report: AuditReport, *, threshold: Severity | None) -> str:
    payload = {
        "tool_count": len(report.tools),
        "tools": [
            {
                "name": tool.name,
                "source": tool.source,
                "dialect": tool.dialect,
            }
            for tool in report.tools
        ],
        "counts": report.counts(),
        "threshold": threshold.value if threshold else None,
        "passed": not report.fails_at(threshold),
        "findings": [finding.to_dict() for finding in report.findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_sarif(report: AuditReport) -> str:
    rule_ids = sorted({finding.rule_id for finding in report.findings})
    rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": f"agent tool audit rule {rule_id}"},
        }
        for rule_id in rule_ids
    ]
    results: list[dict[str, Any]] = []
    for finding in report.findings:
        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": _sarif_level(finding.severity),
            "message": {"text": finding.message},
            "properties": {
                "severity": finding.severity.value,
                "tool": finding.tool,
                "path": finding.path,
                "remediation": finding.remediation,
            },
        }
        source = _source_for_tool(report, finding.tool)
        if source:
            result["locations"] = [
                {
                    "physicalLocation": {"artifactLocation": {"uri": source}},
                    "logicalLocations": [{"name": finding.tool, "kind": "function"}],
                }
            ]
        results.append(result)

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-tool-audit",
                        "informationUri": "https://github.com/mertefekurt/agent-tool-audit",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2)


def _sarif_level(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.ERROR}:
        return "error"
    if severity is Severity.WARNING:
        return "warning"
    return "note"


def _source_for_tool(report: AuditReport, tool_name: str) -> str:
    for tool in report.tools:
        if tool.name == tool_name:
            return tool.source
    return ""

