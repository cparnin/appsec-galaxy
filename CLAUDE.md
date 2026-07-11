# CLAUDE.md

AppSec Galaxy — AI-augmented application security scanner (SAST, secrets,
dependencies, SBOM, cross-file analysis, auto-remediation). CLI, local web UI,
GitHub Action, and FastMCP server share one scanner core.

Read [AGENTS.md](AGENTS.md) for security invariants and contributor rules;
[ARCHITECTURE.md](ARCHITECTURE.md) for pipeline and trust boundaries. Both are
binding.

## Commands

```bash
.venv/bin/python -m ruff check src/ mcp/ scripts/ tests/        # lint (CI-blocking)
.venv/bin/python -m mypy src/appsec_galaxy mcp scripts tests    # types (CI-blocking; keep at zero errors)
PYTHON_DOTENV_DISABLED=1 .venv/bin/python -m pytest tests/ -q   # full suite
.venv/bin/python -m pytest tests/test_ai_provider.py -q         # focused example
.venv/bin/appsec-galaxy                                         # interactive CLI
.venv/bin/python -m appsec_galaxy.web_app                       # web UI on :8000
```

Setup if `.venv` is missing: `python3.12 -m venv .venv && .venv/bin/pip install -e ".[web,dev]"`.
After changing dependencies in `pyproject.toml`, regenerate the lock:
`.venv/bin/uv pip compile pyproject.toml --all-extras -o requirements.lock` (never hand-edit it).

## Architecture in one paragraph

`src/appsec_galaxy/main.py` is the CLI + orchestration; `web_app.py` (Flask)
and `mcp/appsec_galaxy_mcp_server.py` (FastMCP, name `appsec-galaxy`) wrap the
same functions. Rule-based scanners live in `src/appsec_galaxy/scanners/`;
all AI calls go through `scanners/ai_scanner.py` only — provider resolution
(`AI_PROVIDER`: `openai` default / `anthropic`), per-depth model + pricing
tables, cached SDK client, retries, token accounting, and
`test_ai_connection()`. Consumers (`auto_remediation/remediation.py`,
`ai_cross_file.py`, `reporting/ai_summary.py`) reuse `_get_ai_client()` /
`_call_ai()` and must never construct SDK clients themselves. Scan artifacts
go under `outputs/` (gitignored, may contain real secrets).

## Hard rules for this repo

- Never make a live model call in tests or CI — mock at the `_call_ai` /
  client boundary. A one-token live call is acceptable only via the user
  explicitly running `test_ai_connection()` paths.
- Never read or print `.env` or `mcp/mcp_env` values; key *presence* checks
  only. Examples stay placeholder-only (`your-...-here`).
- Scanned repos, filenames, and model output are hostile input — keep the
  XML-wrapping/sanitization in prompts and one-line-only remediation rules.
- The old employer/product identities (tekstream, iris, bedrock, gemini) must
  not reappear anywhere; `tests/test_appsec_galaxy.py` and
  `tests/test_ai_consumers.py` pin these contracts.
- When touching provider logic, update together: `DEPTH_MODEL_MAP`,
  `MODEL_PRICING`, `env.example`, `mcp/mcp_env.example`, `action.yml` inputs,
  README tables, and the tests named above.
- One commit per reviewed unit of work; **never push** — the user pushes.

## Known state

- `.gitleaksignore` (root) suppresses this repo's intentional fake-secret
  fixtures for raw `gitleaks dir .` scans; `.appsec-galaxy-ignore` is the
  app-level baseline when AppSec Galaxy scans itself. Add new fake secrets to
  both if you create test fixtures that look like credentials.
