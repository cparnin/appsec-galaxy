# AppSec Galaxy tests

One file per area of the system:

| File | Covers |
| --- | --- |
| `test_scanners.py` | scanner adapters, parsing, the `Finding` shape, path/binary validation |
| `test_dependency_analysis.py` | manifests, import resolution, registry lookups, CVE reachability |
| `test_ai_analysis.py` | prompt-injection defenses, cross-file AI, summaries, privacy tiers, cost caps |
| `test_ai_provider.py` | provider resolution, models, pricing, retries, token accounting |
| `test_ai_consumers.py` | the modules that call the AI boundary, including remediation fixes |
| `test_remediation.py` | auto-fix safety: protected files, sandboxing, confinement, fork-PR gate |
| `test_pipeline_cli.py` | orchestration, `finalize_scan`, menus, baselines, diff scoping, history |
| `test_reporting.py` | HTML report, SARIF, markdown, shared summary statistics |
| `test_interfaces.py` | web API, MCP server, CI gate, machine-facing identity |

## Run the suite

From the repository root:

```bash
PYTHON_DOTENV_DISABLED=1 .venv/bin/python -m pytest tests/ -q
```

`PYTHON_DOTENV_DISABLED=1` prevents tests from loading a developer's local
credential file. Provider/client tests also unset `OPENAI_API_KEY` and
`ANTHROPIC_API_KEY` and replace
every SDK/model boundary, so CI never makes a live model request.

## Focused suites

```bash
.venv/bin/python -m pytest tests/test_ai_provider.py -q
.venv/bin/python -m pytest tests/test_scanners.py -q
.venv/bin/python -m pytest tests/test_interfaces.py -k MCP -q
.venv/bin/python -m pytest tests/ -k AppSecGalaxyIgnore -q
```

## Test rules

- Use `tmp_path` for repository, output, and baseline fixtures.
- Mock subprocesses and optional scanner binaries unless the test explicitly
  verifies a locally available tool.
- Never read `.env` or `mcp/mcp_env`.
- Never construct a real provider client or send a network request.
- Assert fail-open behavior where failures must preserve findings.
- Assert fail-closed behavior at credential, path, command, remediation, and
  output-sanitization boundaries.
- Keep machine-interface tests aligned with the GitHub Action, workflows, MCP
  server, console command, and public resource schemes.

## Quality gates

Ruff, mypy, and pytest all gate CI; the exact commands are in `CLAUDE.md`
under Commands. The GitHub workflow runs the full suite on Python 3.11,
3.12, and 3.13.
