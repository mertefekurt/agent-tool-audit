<p align="center">
  <img src="assets/readme-cover.svg" alt="Agent Tool Audit cover" width="100%" />
</p>

# Agent Tool Audit

![stack](https://img.shields.io/badge/stack-Python-2563eb?style=flat-square) ![python](https://img.shields.io/badge/python-3.11-16a34a?style=flat-square) ![license](https://img.shields.io/badge/license-MIT-dc2626?style=flat-square) ![ci](https://img.shields.io/badge/ci-GitHub%20Actions-7c3aed?style=flat-square)

Audit AI agent tool manifests for least-privilege and schema risks.

## Good for

- quick local checks around agent reliability
- small CI jobs where a readable report is enough
- review workflows that need deterministic output
- examples based on `examples/risky-tools.json`

## Run it

```bash
python -m pip install -e ".[dev]"
agent-tool-audit examples/risky-tools.json
agent-tool-audit examples/risky-tools.json --json --fail-on medium
```

## Project notes

- Command: `agent-tool-audit`
- Language: Python
- Python: `>=3.11`
- Tests: `pytest`

## Layout

```text
.github/        CI workflow
examples/       sample inputs
src/            package source
tests/          test coverage
.gitignore      project file
pyproject.toml  package metadata
```

## Check locally

```bash
python -m pip install -e ".[dev]"
ruff check .
pytest
python -m agent_tool_audit --help
```
