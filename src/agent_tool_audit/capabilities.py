from __future__ import annotations

import re
from enum import StrEnum

from agent_tool_audit.models import ToolDefinition


class Capability(StrEnum):
    CODE_EXECUTION = "code_execution"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK_SEND = "network_send"
    SECRET_ACCESS = "secret_access"
    DESTRUCTIVE = "destructive"
    FINANCIAL_MUTATION = "financial_mutation"
    IDENTITY_ADMIN = "identity_admin"


_KEYWORDS: dict[Capability, tuple[str, ...]] = {
    Capability.CODE_EXECUTION: (
        "shell",
        "execute command",
        "run command",
        "run code",
        "terminal",
        "subprocess",
        "eval code",
    ),
    Capability.FILE_READ: (
        "read file",
        "get file",
        "load file",
        "download file",
        "filesystem read",
    ),
    Capability.FILE_WRITE: (
        "write file",
        "create file",
        "edit file",
        "move file",
        "filesystem write",
    ),
    Capability.NETWORK_SEND: (
        "send webhook",
        "http post",
        "upload",
        "send email",
        "publish",
        "network request",
        "call api",
    ),
    Capability.SECRET_ACCESS: (
        "secret",
        "credential",
        "api key",
        "password",
        "access token",
        "environment variable",
    ),
    Capability.DESTRUCTIVE: (
        "delete",
        "remove",
        "drop",
        "purge",
        "terminate",
        "revoke",
        "destroy",
    ),
    Capability.FINANCIAL_MUTATION: (
        "refund",
        "charge",
        "payment",
        "transfer money",
        "payout",
        "invoice",
    ),
    Capability.IDENTITY_ADMIN: (
        "create user",
        "delete user",
        "change role",
        "grant access",
        "revoke access",
        "invite user",
        "permission",
    ),
}


def classify(tool: ToolDefinition) -> set[Capability]:
    normalized_name = re.sub(r"[_-]+", " ", tool.name.lower())
    corpus = f"{normalized_name} {tool.description.lower()}"
    return {
        capability
        for capability, keywords in _KEYWORDS.items()
        if any(keyword in corpus for keyword in keywords)
    }

