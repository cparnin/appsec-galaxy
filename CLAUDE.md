# AppSec Galaxy - Security Scanner Operating Manual

## Standing Rules for AI Assistants (READ FIRST)

These rules override any default behavior. Follow them on every task in this
repo, without waiting to be asked. Refine them over time; treat this section
as the source of truth for how to work on AppSec Galaxy.

1. **Always add tests for new features and bug fixes.**
   Any change that adds a function, fixes a bug, or changes observable
   behavior ships with tests under `tests/`. Pure functions (parsers,
   normalizers, classifiers) get unit tests. Orchestrators get tests with
   mocked external calls (AI SDKs, subprocess, filesystem). Regression tests
   must assert the specific failure mode, not just "it runs." If something
   cannot be tested, say why.

2. **Always update ALL relevant documentation alongside code, concisely.**
   Every code change ships with doc updates in the same commit. Touch every
   file the change makes stale: `CLAUDE.md`, `README.md`, `AGENTS.md`,
   `env.example`, `mcp/mcp_env.example`, `CHANGELOG.md`, `clients/SETUP.md`
   if client behavior changed. One or two sentences per change, not essays.
   Stale docs are a bug.

   **README.md specifically** is user-facing and gets stale fastest. Update
   it without being asked when ANY of the following change:
   - Setup or install steps (`.env` keys, env-var names, required tools)
   - AI provider or model defaults
   - Removed or renamed features, env vars, or CLI flags
   - New scanners, deployment modes, or MCP tools
   - Any number quoted in the README (test count, language list, prices)
   Before declaring a task done, re-read README.md and ask: "does anything I
   just changed make a line in here a lie?" If yes, fix it in the same commit.

3. **Always run the full gates before declaring work done.**
   `ruff` + `mypy` + `pytest` (commands below). All three are CI-blocking.
   Never mark a task complete with failures unless you explicitly note they
   are pre-existing and unrelated.

4. **Refer back to this file proactively.**
   Before starting a non-trivial task, re-read the relevant section. When
   something here is wrong, stale, or incomplete, fix it in the same commit.

5. **Prefer editing existing files over creating new ones.**
   Never create new `.md` files (READMEs, design docs) unless explicitly
   asked. Extend `CLAUDE.md`, `README.md`, or `ARCHITECTURE.md` instead.

6. **Never make a live AI/model call in tests or CI.**
   Mock at the `_call_ai` / `_get_ai_client` boundary. The only sanctioned
   live call is the one-token `test_ai_connection()` probe a user triggers
   interactively (CLI picker or web scan start).

7. **Never read or print `.env` or `mcp/mcp_env` values.**
   Key presence checks only (name-anchored grep or `os.getenv` truthiness).
   Committed examples stay placeholder-only (`your-...-here`).

8. **Never use em dashes anywhere.**
   Not in docs, commit messages, PR descriptions, code comments, or generated
   reports. Use a comma, a period, parentheses, or a colon instead. This
   applies to en dashes too. Hyphens in compound words and CLI flags are fine.

9. **Go easy on emojis.**
   Use sparingly and only where a glyph carries real signal (status
   indicators in scan output). Never add decorative emojis; thin them out
   when rewriting emoji-dense content.

10. **Manage release tags proactively.**
    When a meaningful batch of Unreleased CHANGELOG entries ships, graduate
    them to a dated `## [X.Y.Z]` section, bump `version` in pyproject.toml
    and `src/appsec_galaxy/__init__.py`, tag `vX.Y.Z` on main, and create a
    GitHub release. Semver: patch for fixes, minor for features, major for
    breaking changes to env vars, action inputs, or MCP tools. Client
    workflows may pin `uses: cparnin/appsec-galaxy@vX.Y.Z`; never move or
    delete published tags.

11. **Commit freely; push only after we agree in-session to push.**
    Commit locally as work lands. Pushing to the remote requires an explicit
    go-ahead from the user in the current session (a standing "you can push"
    does not carry across sessions). Never force-push, never rewrite published
    history, never touch the private upstream reference checkout (read-only;
    its path lives in Claude's project memory, deliberately not in this
    repository).

## Project Overview

**AppSec Galaxy** ("Application security, mapped.") is an AI-augmented
application security scanner: rule-based SAST, secrets, and dependency
scanning plus optional AI analysis that finds logic flaws, auth bypasses,
race conditions, and cross-file attack chains that rules cannot.

**Codebase:** ~19,000 lines of Python (src, mcp, scripts) plus a pytest
suite (493 tests, ~7s). Personal project of cparnin; MIT licensed.

## Deployment Modes (all share the same scanner core)

### CLI: `.venv/bin/appsec-galaxy` (or `python -m appsec_galaxy.main`)
Interactive menus: repository picker, tool selection, severity level, AI
provider picker (key status + live connection test), AI privacy tier picker
(select_privacy_tier; tiers 1-2 drop the AI scanner from the run), auto-fix
options.

### Web: `python -m appsec_galaxy.web_app` (port 8000, `./start_web.sh`)
Same options as checkboxes/dropdowns, including the AI Provider dropdown
populated from `/config` (default model + key status per provider) and an AI
Data Privacy dropdown (tier; selecting 1 or 2 disables the AI Deep Analysis
checkbox). `/scan` accepts `ai_provider` and `ai_scan_tier`, fails fast with
a clear message when the provider is unusable, and rejects `ai_scan` at
tiers 1-2. Galaxy brandmark backdrop renders bottom-right in dark mode
(`images/appsec-galaxy-mark.svg`; hidden in light mode).

### GitHub Actions: `action.yml` + `clients/security-scan.yml`
Declarative provider choice: `ai-provider` input (`openai` default or
`anthropic`) with `openai-api-key` / `anthropic-api-key` secrets;
`ai-scan-tier` input maps to `APPSEC_AI_SCAN_TIER`. Startup
validation fails the job naming the missing key env var. `fail-on-critical`
gates via `scripts/fail_on_critical.py` (`APPSEC_FAIL_THRESHOLD`).

### MCP: `mcp/appsec_galaxy_mcp_server.py` (FastMCP, name `appsec-galaxy`)
16 tools + 4 `appsec-galaxy://` resources for ChatGPT desktop, Codex, Claude
Desktop, and other MCP clients. Import/initialization is offline: it must
never construct an AI client or require a key. Credentials live in the
server process environment only.

## AI Provider Boundary (the most important module contract)

Everything AI goes through `src/appsec_galaxy/scanners/ai_scanner.py`:
provider resolution, per-depth model and pricing tables, cached SDK client,
retries (3 attempts, transient errors only), token/cost accounting, and
`test_ai_connection()`. Consumers (`auto_remediation/remediation.py`,
`ai_cross_file.py`, `reporting/ai_summary.py`) reuse `_get_ai_client()` /
`_call_ai()` and never construct SDK clients themselves.

- `AI_PROVIDER`: blank/unset/`openai` resolve to OpenAI (Responses API);
  `anthropic` selects Anthropic (Messages API); anything else is a loud
  configuration error.
- Keys: `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` to match the provider;
  required only when AI scanning or auto-remediation is enabled.
- Depth models (override with `APPSEC_AI_SCAN_MODEL`, then `AI_MODEL`):

  | Depth | OpenAI | Anthropic | Notes |
  | --- | --- | --- | --- |
  | quick | gpt-5.6-luna | claude-haiku-4-5 | no verification pass; PR-diff scans |
  | standard | gpt-5.6-terra | claude-sonnet-5 | default; verification pass on |
  | deep | gpt-5.6-sol | claude-opus-4-8 | thorough audit; highest cost |

- Keep `DEPTH_MODEL_MAP`, `MODEL_PRICING`, `env.example`,
  `mcp/mcp_env.example`, `action.yml`, and README tables aligned when any of
  them changes.
- Prompt-injection defense: stable instructions go in the system channel
  (OpenAI `instructions`, Anthropic `system`); untrusted code goes in the
  user message wrapped in `<source_file>` tags with `_xml_safe_path()`
  sanitized paths. Scanned repos are hostile input.
- Cost visibility: token usage and estimated USD print after every scan and
  land in `outputs/<repo>/raw/ai_scan.json`. `APPSEC_AI_SCAN_MAX_FILES`
  (default 50) is the main cost lever; when the cap drops candidates a
  warning names the count and the env var.

## Architecture Map

```
src/appsec_galaxy/
├── main.py                  # CLI orchestration, interactive menus, provider picker
├── web_app.py               # Flask UI/API (X-API-Key auth optional, CORS opt-in)
├── config.py                # Hardcoded constants + pydantic-settings validation
├── cross_file_analyzer.py   # AST-based attack-chain engine (10+ languages)
├── ai_cross_file.py         # LLM chain validation / correlation / sanitization
├── enhanced_analyzer.py     # Cross-file enhancement layer
├── finding.py               # Canonical Finding dataclass (scanner boundary)
├── scan_filters.py          # .appsec-galaxy-ignore baseline + APPSEC_DIFF_ONLY
├── scan_history.py          # Trend history (new vs fixed per scan)
├── vuln_intel.py            # EPSS / CISA-KEV enrichment + reachability-based CVE priority
├── sbom_generator.py        # CycloneDX + SPDX SBOMs
├── scanners/                # semgrep, gitleaks, trivy (deps + IaC misconfig), ai_scanner, linters
├── auto_remediation/        # one-line AI fixes + PR creation (remediation.py)
├── reporting/               # html.py, sarif.py, ai_summary.py + templates
└── templates/index.html     # web UI (single file, inline CSS/JS)

mcp/appsec_galaxy_mcp_server.py   # FastMCP server + AppSecGalaxyMCPCore
scripts/fail_on_critical.py       # CI gate
configs/                          # bundled scanner configs (.gitleaks.toml etc.)
clients/                          # drop-in workflow + SETUP.md
tests/                            # test_appsec_galaxy.py, test_ai_provider.py,
                                  # test_ai_consumers.py, conftest.py
outputs/                          # generated, gitignored, may contain secrets
```

## Commands

```bash
# Gates (all CI-blocking; run all three before declaring done)
.venv/bin/python -m ruff check src/ mcp/ scripts/ tests/
.venv/bin/python -m mypy src/appsec_galaxy mcp scripts tests
PYTHON_DOTENV_DISABLED=1 .venv/bin/python -m pytest tests/ -q

# Focused tests while developing
.venv/bin/python -m pytest tests/test_ai_provider.py -q
.venv/bin/python -m pytest tests/test_appsec_galaxy.py -k "TestMachineFacingIdentity" -q

# Setup / dependency changes
python3.12 -m venv .venv && .venv/bin/pip install -e ".[web,dev]"
.venv/bin/uv pip compile pyproject.toml --all-extras -o requirements.lock

# MCP offline smoke (must print exactly: appsec-galaxy)
PYTHONPATH=src APPSEC_GALAXY_PATH="$PWD" .venv/bin/python -c \
  'import importlib.util; s=importlib.util.spec_from_file_location("m","mcp/appsec_galaxy_mcp_server.py"); \
   m=importlib.util.module_from_spec(s); s.loader.exec_module(m); m.AppSecGalaxyMCPCore(); print(m.SERVER_NAME)'
```

Tests must pass with `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` unset; AI
module tests monkey-patch `_get_ai_client` / `_call_ai`.

## Configuration

`.env` (from `env.example`) is the single user-facing knob file; `config.py`
validates all `APPSEC_*` vars at startup via pydantic-settings and fails
loudly on bad values. Key groups:

- Provider: `AI_PROVIDER`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
  `AI_MODEL`, `APPSEC_AI_SCAN_MODEL`
- AI scan: `APPSEC_AI_SCAN` (off by default), `APPSEC_AI_SCAN_DEPTH`,
  `APPSEC_AI_SCAN_MAX_FILES`, `APPSEC_AI_SCAN_TIER` (privacy: 1 none,
  2 snippets, 3 full source), `APPSEC_AI_CROSS_FILE_MAX_*` cost caps
- Scanning: `APPSEC_SCAN_LEVEL` (security), `APPSEC_CODE_QUALITY_MIN_SEVERITY`
  (quality; independent filters), `APPSEC_TOOLS`, `APPSEC_DIFF_ONLY`/`_BASE`,
  `APPSEC_TRIVY_SCANNERS` (default `vuln,misconfig`; `vuln` reverts to
  dependency CVEs only)
- Auto-fix: `APPSEC_AUTO_FIX`, `APPSEC_AUTO_FIX_MODE` (1 SAST, 2 deps,
  3 both, 4 skip), `GITHUB_TOKEN` (repo scope, PR creation only)
- Web: `HOST` (default 127.0.0.1), `PORT`, `APPSEC_WEB_API_KEY`,
  `APPSEC_WEB_CORS_ORIGINS`, `APPSEC_ENABLE_DIRECTORY_BROWSING`,
  `APPSEC_ALLOWED_SCAN_ROOTS` (confine scan targets; recommended off-localhost)
- MCP: `APPSEC_GALAXY_PATH`, `APPSEC_MCP_ALLOWED_ROOTS` (scan-target
  allowlist), `MCP_SCAN_TIMEOUT`, `MCP_REMEDIATE_TIMEOUT`

Every env var the code reads must appear in `env.example` or
`mcp/mcp_env.example`; every documented var must be read by code. Audit with
a name-only grep when touching configuration.

## Security Invariants (summary; full list in AGENTS.md)

- Untrusted everything: scanned repos, filenames, findings, model output.
- `shell=False` argument arrays; validate paths before subprocess/filesystem.
- Baseline and diff filters fail open; AI verification failures preserve
  original findings; cross-file/report AI failures degrade to static output.
- Remediation: one-line replacements only, indentation preserved, protected
  files and secrets excluded, multi-line model output rejected. AI code
  fixes are privacy-tier gated (`APPSEC_AI_SCAN_TIER` < 3 skips them; the
  fix prompt carries source context). Dependency bumps make no AI calls. Every applied
  fix passes `validate_file_syntax()`; a result that no longer parses is
  reverted (never committed). Additive findings (e.g. Docker missing-USER)
  are not auto-fixable because replace-mode cannot insert a line. Lockfile
  regeneration never runs untrusted repo code: npm/yarn use `--ignore-scripts`,
  `go get` uses `GOTOOLCHAIN=local`. Auto-remediation is forced off on CI
  fork pull requests (`is_untrusted_pr_context()` + the Action env gate):
  a fork checkout is outside code and remediation commits/pushes/opens PRs.
  Same-repo PRs and pushes are trusted and auto-fix normally.
- Fake-secret fixtures need suppression in BOTH `.gitleaksignore`
  (fingerprints, for raw gitleaks) and `.appsec-galaxy-ignore` (app baseline).
- Never log secret values anywhere, including examples and test fixtures.

## Troubleshooting Quick Answers

**"No vulnerabilities found?"** Check `APPSEC_SCAN_LEVEL=all`, verify raw
scanner output in `outputs/<repo>/raw/`.

**"AI feature unavailable / key error?"** The error names the exact env var
(`OPENAI_API_KEY` or `ANTHROPIC_API_KEY`) for the active provider. The CLI
picker and web scan run a one-token connection test that classifies bad key
vs unknown model vs network before any scan spend.

**"Auto-fix not creating PRs?"** `GITHUB_TOKEN` with repo scope; in Actions,
`contents: write` + `pull-requests: write` permissions.

**"AI scan cost too high?"** Lower `APPSEC_AI_SCAN_DEPTH` (quick uses the
cheapest tier and skips verification), reduce `APPSEC_AI_SCAN_MAX_FILES`,
check the printed per-scan cost and `ai_scan.json` token usage.

**"Watermark/logo missing in web UI?"** Dark mode only by design;
`images/appsec-galaxy-mark.svg` served via `/images/`, wired in
`templates/index.html` `body::before`.

## Recent History (context for why things are the way they are)

- 2026-07-11: Migrated from a private work project to personal AppSec
  Galaxy. Renamed package/CLI/MCP/action, OpenAI as default provider, then
  added Anthropic as a second provider with CLI + web pickers and a live
  connection test. All mypy debt cleared (gate blocking). The former
  employer, product, and provider identities are banned; the exact strings
  live rot13-encoded in the identity tests (TestMachineFacingIdentity and
  the consumer residue tests), so they never appear in this tree.
- The private upstream checkout is a read-only reference and must never be
  modified (see rule 11).
