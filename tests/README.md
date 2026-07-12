# AppSec Galaxy tests

The suite covers scanner parsing and failure behavior, path and subprocess
security, cross-file analysis, reporting, remediation safety, AI provider boundaries,
MCP tools/resources, web smoke behavior, baselines, SARIF/SBOM metadata, and
machine-facing configuration.

## Run the suite

From the repository root:

```bash
PYTHON_DOTENV_DISABLED=1 .venv/bin/python -m pytest tests/ -v --tb=short
```

`PYTHON_DOTENV_DISABLED=1` prevents tests from loading a developer's local
credential file. Provider/client tests also unset `OPENAI_API_KEY` and
`ANTHROPIC_API_KEY` and replace
every SDK/model boundary, so CI never makes a live model request.

## Focused suites

```bash
.venv/bin/python -m pytest tests/test_openai_provider.py -q
.venv/bin/python -m pytest tests/test_openai_consumers.py -q
.venv/bin/python -m pytest tests/test_appsec_galaxy.py -k MCP -q
.venv/bin/python -m pytest tests/test_appsec_galaxy.py -k AppSecGalaxyIgnore -q
```

## Test rules

- Use `tmp_path` for repository, output, and baseline fixtures.
- Mock subprocesses and optional scanner binaries unless the test explicitly
  verifies a locally available tool.
- Never read `.env` or `mcp/mcp_env`.
- Never construct a real OpenAI client or send a network request.
- Assert fail-open behavior where failures must preserve findings.
- Assert fail-closed behavior at credential, path, command, remediation, and
  output-sanitization boundaries.
- Keep machine-interface tests aligned with the GitHub Action, workflows, MCP
  server, console command, and public resource schemes.

## Quality gates

```bash
.venv/bin/python -m ruff check src/ mcp/ scripts/ tests/
.venv/bin/python -m mypy src/appsec_galaxy mcp scripts tests
```

The GitHub workflow runs the full suite on Python 3.11, 3.12, and 3.13.
