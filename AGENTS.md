# AppSec Galaxy contributor instructions

## Product identity

- Product: AppSec Galaxy
- Tagline: Application security, mapped.
- Distribution and command: `appsec-galaxy`
- Python package: `appsec_galaxy`
- Repository: `cparnin/appsec-galaxy`
- License: MIT

Use project-neutral open-source language. Do not add employer names, private
repository locations, personal contact details, or old product/provider names.

## Repository map

- `src/appsec_galaxy/`: application package, scanners, reporting, and web UI
- `mcp/appsec_galaxy_mcp_server.py`: FastMCP server and resources
- `scripts/`: tested CI/security gates
- `configs/`: bundled scanner configurations
- `clients/`: reusable GitHub workflow and setup guide
- `tests/`: unit, integration, and machine-interface contracts
- `images/`: public documentation and web assets
- `outputs/`: generated sensitive scan artifacts; never commit

## Setup

Use Python 3.11-3.13.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e ".[web,dev]"
```

Gitleaks, Trivy, Syft, and language linters are external tools. Tests must not
assume they are installed unless the specific test supplies a fake executable.

## Verification

Run these exact repository gates before proposing a commit:

```bash
.venv/bin/python -m ruff check src/ mcp/ scripts/ tests/
.venv/bin/python -m mypy src/appsec_galaxy mcp scripts tests
PYTHON_DOTENV_DISABLED=1 .venv/bin/python -m pytest tests/ -v --tb=short
```

Also run focused tests while developing. Do not claim success from an earlier
run; verification evidence must reflect the current working tree.

## Security invariants

- Treat scanned repositories, filenames, findings, model output, and tool
  output as untrusted.
- Use argument arrays with `shell=False`; validate paths before filesystem or
  subprocess access.
- Never log secret values or include them in reports, history, test fixtures,
  MCP config, or committed examples.
- Generated output belongs under `outputs/` and stays untracked.
- Baseline and diff filters fail open. A malformed baseline or missing Git ref
  must not suppress findings.
- AI verification failures preserve original findings.
- Auto-remediation never edits protected workflow/credential files, accepts
  only one-line replacements, preserves indentation, and rejects multi-line
  model output. Every applied fix is syntax-validated (`validate_file_syntax`)
  and reverted if the result no longer parses, so broken code is never
  committed. Additive findings (line insertion) are excluded from auto-fix.
- Parse untrusted XML with hardened libraries and render untrusted report data
  with HTML autoescaping.

## AI provider boundary

`AI_PROVIDER` may be blank, unset, `openai` (default), or `anthropic`; every
other nonblank value is a configuration error. The provider's API key
(`OPENAI_API_KEY` or `ANTHROPIC_API_KEY`) is required only when AI scanning or
automated remediation is enabled.

All model calls go through `scanners/ai_scanner.py` -- the OpenAI Responses
API or the Anthropic Messages API depending on `AI_PROVIDER`. Keep stable
instructions separate from dynamic/untrusted input. Mock the client and call
boundary in tests; never make a live model request in CI.

Default depth models are `gpt-5.6-luna`/`gpt-5.6-terra`/`gpt-5.6-sol` for
OpenAI and `claude-haiku-4-5`/`claude-sonnet-5`/`claude-opus-4-8` for
Anthropic.
Keep pricing and model tables aligned when updating them.

## MCP architecture

The server name is `appsec-galaxy`, exports 16 generic tools, and exposes four
`appsec-galaxy://` resource templates. Importing and initializing the MCP core
must not construct an OpenAI client or require an API key. Keep secrets in the
server process environment, never in `.codex/config.toml` or client JSON.

## Documentation and changelog

- Update README usage when commands, environment variables, or public outputs
  change.
- Put detailed pipeline and trust-boundary explanations in `ARCHITECTURE.md`;
  link to them instead of duplicating them.
- Add user-visible changes to `CHANGELOG.md` under `Unreleased`.
- Keep examples placeholder-only and verify every local Markdown link.

## Release and Git rules

- Keep `pyproject.toml`, package `__version__`, SBOM metadata, action examples,
  and release notes aligned.
- Regenerate `requirements.lock` from `pyproject.toml` with all extras; do not
  hand-edit a resolved lock.
- Preserve unrelated user changes and never use destructive Git commands.
- Do not commit generated scan outputs or local credential files.
- Do not push, publish, tag, or open a pull request until the complete diff has
  passed tests and explicit review. A local commit is not permission to push.
