from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.WARNING: 1,
            Severity.ERROR: 2,
            Severity.CRITICAL: 3,
        }[self]


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    name: str
    description: str
    input_schema: dict[str, Any]
    source: str
    dialect: str


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    message: str
    tool: str
    path: str = ""
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "tool": self.tool,
            "path": self.path,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass(slots=True)
class AuditReport:
    tools: list[ToolDefinition]
    findings: list[Finding] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {
            severity.value: sum(finding.severity is severity for finding in self.findings)
            for severity in Severity
        }

    def fails_at(self, threshold: Severity | None) -> bool:
        if threshold is None:
            return False
        return any(finding.severity.rank >= threshold.rank for finding in self.findings)

