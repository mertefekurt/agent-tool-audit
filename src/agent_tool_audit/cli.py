from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from agent_tool_audit import __version__
from agent_tool_audit.analyzer import audit_tools
from agent_tool_audit.loaders import ManifestError, load_manifest
from agent_tool_audit.models import AuditReport, Severity
from agent_tool_audit.reporters import render_json, render_sarif, render_terminal


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-tool-audit",
        description=(
            "Audit OpenAI, Anthropic, MCP, and raw function tool manifests for "
            "least-privilege and schema risks."
        ),
    )
    parser.add_argument("manifest", nargs="+", help="JSON manifest file to audit")
    parser.add_argument(
        "--format",
        choices=("terminal", "json", "sarif"),
        default="terminal",
        help="report format (default: terminal)",
    )
    parser.add_argument("--output", type=Path, help="write the report to a file")
    parser.add_argument(
        "--fail-on",
        choices=("warning", "error", "critical", "none"),
        default="error",
        help="minimum severity that returns exit code 1 (default: error)",
    )
    parser.add_argument(
        "--ignore-rule",
        action="append",
        default=[],
        metavar="RULE",
        help="suppress a rule ID; repeat for multiple rules",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        tools = [tool for path in args.manifest for tool in load_manifest(path)]
    except ManifestError as exc:
        print(f"agent-tool-audit: {exc}", file=sys.stderr)
        return 2

    report = audit_tools(tools, ignored_rules=set(args.ignore_rule))
    threshold = None if args.fail_on == "none" else Severity(args.fail_on)
    rendered = _render(args.format, report, threshold)

    if args.output:
        try:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"agent-tool-audit: cannot write {args.output}: {exc}", file=sys.stderr)
            return 2
    else:
        print(rendered)
    return 1 if report.fails_at(threshold) else 0


def _render(format_name: str, report: AuditReport, threshold: Severity | None) -> str:
    if format_name == "json":
        return render_json(report, threshold=threshold)
    if format_name == "sarif":
        return render_sarif(report)
    return render_terminal(report, threshold=threshold)
