# Changelog

All notable AppSec Galaxy changes are documented here. The project follows
semantic versioning.

## Unreleased

## [2.6.0] - 2026-07-17

### Added

- The AI scanner honors `APPSEC_DIFF_ONLY`: with diff mode on, only files
  changed vs the base ref are selected for AI analysis (fail-open to a
  full-repo selection when the diff is unavailable, matching the rule-based
  scanners). Makes per-PR AI scans cost cents instead of a full-repo pass.
- `APPSEC_AI_SCAN_MAX_COST` (Action input `ai-scan-max-cost`): a hard USD
  ceiling for the AI scanner phase. Spend is re-estimated between AI calls
  and the scan stops issuing new ones at the cap; the verification pass is
  skipped fail-safe (findings kept unverified) when the cap is already
  spent. The self-scan weekly AI run is capped at $1.00.
- Anthropic prompt caching: the system prompt is sent as an ephemeral cache
  breakpoint (OpenAI caches shared prefixes automatically). Cache reads
  were already tracked and discounted at the `cached_input` rate; this
  makes Anthropic actually produce them. Dormant below the API's
  1024-token cacheable minimum.
- Self-scan uploads SARIF to GitHub Code Scanning (free on public repos),
  so findings land in the Security tab with PR annotations.

### Changed

- Semgrep rulesets are pinned (`p/default`) instead of `--config auto`, so
  the same code produces the same findings across CLI, CI, and time.
  Override with `APPSEC_SEMGREP_CONFIG` (comma-separated; `auto` restores
  the old dynamic selection).

## [2.5.0] - 2026-07-17

### Added

- The AI privacy tier (`APPSEC_AI_SCAN_TIER`) is now settable from every
  deployment mode instead of `.env` only: an interactive CLI picker (shown
  when the AI scanner is selected), an AI Data Privacy dropdown in the web
  UI (`/scan` accepts `ai_scan_tier`, `/config` reports the default), and a
  new `ai-scan-tier` Action input mapped to `APPSEC_AI_SCAN_TIER`.
- `TestPrivacyTierContract`: pins the composite privacy-tier behavior across
  the split gates (`tier < 3` in ai_scanner and ai_cross_file, `tier < 2` in
  ai_summary) so the README privacy table and the code cannot drift apart.
  Includes sentinel tests that no AI client is ever constructed at tiers 1-2
  in the source-sending paths, and that secret values never enter the
  findings digest.

### Fixed

- Auto-remediation now honors the privacy tier: generating an AI code fix
  sends the vulnerable line plus context to the AI provider, so tiers 1
  and 2 skip AI code fixes with a clear message (previously remediation
  ignored the tier entirely). Dependency version bumps make no AI calls
  and still work at every tier. The web `/scan` endpoint also rejects
  contradictory requests (AI deep analysis at tier 1 or 2) instead of
  silently scanning without AI, and restores all env overrides on its
  fail-fast error paths (previously only `AI_PROVIDER` was restored).

## [2.4.2] - 2026-07-13

### Fixed

- Auto mode (GitHub Action / `python -m appsec_galaxy.main`) crashed with
  `UnboundLocalError: enhanced_findings` when a scan found zero findings:
  the variable was bound only in the has-findings branch but returned
  unconditionally. A clean repo scanned in CI (including the self-scan once
  the tree scanned clean) failed the job. Now bound before the branch.
  Regression test added.

## [2.4.1] - 2026-07-13

### Changed

- Auto-remediation is now suppressed only on FORK pull requests, not all
  pull requests. v2.4.0 blocked every pull_request event; that also blocked
  the maintainer's own same-repo PRs, which are trusted. Fork detection uses
  `github.event.pull_request.head.repo.fork` (Action) and the event payload
  (`is_untrusted_pr_context`), failing closed when the payload is unreadable.
  Same-repo PRs and pushes create fix PRs normally again.

## [2.4.0] - 2026-07-13

### Security

- PR body text is sanitized against Markdown injection. Auto-remediation PR
  bodies interpolate finding messages, file paths, package names, and
  AI-derived attack-chain descriptions, all originating from the scanned
  repo. New `sanitize_markdown_field` defuses links/images (tracking pixels,
  phishing), `@mentions` (notification spam), raw HTML, and code-fence
  breakouts before they reach `gh pr create --body`. PR titles were already
  sanitized; this closes the body.
- Web server defaults fail closed. The dev server now binds `127.0.0.1` by
  default instead of `0.0.0.0` (exposing it on all interfaces is now a
  deliberate `HOST=0.0.0.0` opt-in), and CORS no longer falls back to a
  wildcard when `APPSEC_WEB_CORS_ORIGINS` is unset (it adds no CORS headers
  at all, so a malicious site cannot script the locally-running scanner).
- Scan targets can be confined to an allowlist of directories, closing an
  arbitrary-path / source-disclosure hole on the two surfaces where the
  caller is not fully trusted. The MCP server now rejects `..` traversal and
  confines every resolved repo to its search roots (override with
  `APPSEC_MCP_ALLOWED_ROOTS`); the web `/scan` validator enforces
  `APPSEC_ALLOWED_SCAN_ROOTS` when set. Containment uses realpath +
  commonpath so symlinks and `..` cannot escape.
- Auto-remediation no longer runs against untrusted PR code. On any
  `pull_request` event the checkout is the PR head (a fork can supply
  anything) and remediation commits, pushes, and opens a PR, so it is now
  forced off at two layers: the Action sets `APPSEC_AUTO_FIX` off on
  pull_request events, and the scanner itself downgrades to scan-only via a
  new `is_untrusted_pr_context()` check. Fix PRs are created on push and
  workflow_dispatch only.
- Auto-remediation no longer executes untrusted repo code when regenerating
  lockfiles. `npm install` and `yarn install` now run with `--ignore-scripts`
  (blocking preinstall/postinstall/prepare lifecycle scripts from the scanned
  repo, which were an arbitrary-code-execution vector on the scan host and CI
  runners), and `go get` runs with `GOTOOLCHAIN=local` (refusing to download
  and run a Go toolchain named in a hostile go.mod).

### Added

- Trivy now scans IaC and config misconfigurations (Terraform, CloudFormation,
  K8s manifests, Dockerfile) alongside dependency CVEs. New
  `APPSEC_TRIVY_SCANNERS` env var (default `vuln,misconfig`; set `vuln` for
  the old deps-only behavior). Misconfig findings normalize to the canonical
  Finding with file/line, resolution guidance, and are excluded from
  dependency auto-fix. Misconfigs surface everywhere trivy results do: CLI
  and web summaries get a dedicated misconfig count (dependency counts no
  longer include them), the HTML report shows an IaC Misconfigs tile, MCP
  get_scan_findings/get_trivy_findings return them (finding_type
  "misconfiguration"), and the Action job summary plus fail-on-critical
  gate count them (suppressible via .appsec-galaxy-ignore by ID).
- Reachability-aware CVE prioritization: Trivy dependency CVEs are joined to
  the dependency code-path analysis (package-name normalizer handles npm
  scopes, pypi case/extras/separator variants) and each finding gets
  reachability (imported / not-imported / unknown) plus a combined
  risk_priority: imported + KEV/high-EPSS escalates to urgent, declared but
  never imported demotes one level (KEV never below high). The HTML report
  sorts by risk_priority first and shows the reachability evidence; SARIF
  carries reachability and risk_priority properties.
- Secret confidence classification: every gitleaks finding gets an offline
  confidence (high/medium/low) from Shannon entropy plus placeholder and
  test-fixture heuristics (your-...-here, template refs, repeated chars).
  The HTML report sorts real-looking secrets first, MCP findings carry the
  field, and the reason string never contains the secret value. No network;
  live credential validation remains a possible future opt-in.
- SARIF export is now first-class for GitHub Code Scanning: each rule carries
  `security-severity` (drives Security-tab ranking), each result carries
  `partialFingerprints` (dedups alerts across runs and tracks fix/reopen),
  and rules link `helpUri` when the source tool provides a reference.

### Fixed

- Onboarding papercuts a fresh clone would hit: the client CI workflow pinned
  a nonexistent `@v2.2.2` tag (now `@v2.3.0`), the README and mcp/README
  hardcoded `python3.12` (now `python3` with the 3.11-3.13 range noted) and
  named the external scanners without install commands (now `brew install`
  plus release links), `start_web.sh` now also checks for syft and prints the
  actual install command, and `action.yml`'s `ai-model` default was `''''`
  (a literal apostrophe in YAML) instead of an empty string.

### Changed

- Semgrep now runs with `--metrics=off`: `--config auto` sent scan telemetry
  to the Semgrep registry by default, which a tool scanning private or client
  code should not do.

### Fixed

- Auto-remediation no longer commits broken code. Every applied single-line
  fix now passes through a language-aware syntax gate (Python, JS, JSON, YAML,
  shell, Go, Ruby, PHP where the tool is present); a fix whose result fails to
  parse is reverted and flagged for manual review instead of being committed.
  Removed the Docker "missing-USER" finding types from auto-fix: they need
  line insertion, which single-line replacement cannot express (it was
  deleting the ENTRYPOINT).

### Changed

- HTML report is now dark-themed by default (was light) and front-loads the
  AI findings: the AI Deep Analysis section leads the detailed findings
  instead of rendering last.

### Fixed

- Raised per-depth AI output-token caps (8K/16K/32K) and added explicit
  truncation detection with an actionable warning. A vulnerable-enough repo
  (verified live against a deliberately insecure Node app) produced a
  findings array past the old 4K cap, which truncated the JSON and silently
  discarded the whole batch while still billing for it.

## [2.3.0] - 2026-07-12

### Changed

- Renamed the project, package, command, MCP server, resources, GitHub Action,
  runtime metadata, and public documentation to AppSec Galaxy.
- Standardized AI scanning and remediation on the OpenAI Responses API with
  GPT-5.6 depth defaults and strict provider validation.
- Moved the Python package to `src/appsec_galaxy` and added an installed
  `appsec-galaxy` console command.
- Replaced the scan baseline filename with `.appsec-galaxy-ignore`.
- Updated machine-facing workflows, examples, and client setup for
  `OPENAI_API_KEY` and optional model overrides.
- Added an Anthropic provider option (`AI_PROVIDER=anthropic` with
  `ANTHROPIC_API_KEY`); OpenAI remains the default. The interactive CLI and
  the web UI now include a provider picker with key-status display and a live
  connection test; the web `/scan` endpoint accepts `ai_provider` and fails
  fast with a clear error when the provider is unusable.
- Documented previously unlisted environment variables (`GITHUB_TOKEN`,
  `APPSEC_AUTO_FIX`, `APPSEC_AUTO_FIX_MODE`, web server `HOST`/`PORT`/
  `APPSEC_WEB_API_KEY`/`APPSEC_WEB_CORS_ORIGINS`, MCP timeouts) and removed
  the dead `APPSEC_AI_SCAN_MIN_CONFIDENCE` example.
- Cleared all mypy errors across the codebase; the CI mypy gate is blocking.
- Restored the web UI brandmark backdrop with a new AppSec Galaxy galaxy mark
  (`images/appsec-galaxy-mark.svg`); the old template still pointed at the
  removed legacy image, so no backdrop rendered.
- The AI scanner now logs a warning naming `APPSEC_AI_SCAN_MAX_FILES` and the
  skipped-file count whenever the relevance-ranked file cap drops candidates.
- Rewrote `CLAUDE.md` as a full operating manual (standing rules, modes,
  provider boundary, commands, troubleshooting).
- API-key presence checks (CLI picker, web config/scan, startup validation)
  now treat env.example placeholder values (`your-...-here`) as unset, with
  a distinct "still the placeholder" error from the client builder.
- `env.example` now ships `APPSEC_AI_SCAN=false` so a copied example never
  enables AI spend by default (matches the code default).

### Fixed

- LICENSE now names AppSec Galaxy (was the pre-migration project name).
- Former-identity strings removed everywhere; banned terms live rot13-encoded
  in the identity tests.
- Usage analytics no longer crash silently on `datetime.UTC` misuse and now
  report the real package version.
- Skipping auto-fix (mode 4) through the web interface no longer returns a
  crash-prone empty result.

### Security

- Malformed AI verification output now preserves original findings.
- Remediation preserves source indentation and rejects every multi-line model
  response instead of applying a partial fix.
- Invalid required AI configuration now fails CLI/module entrypoints with a
  nonzero exit.
- MCP initialization remains offline and reads credentials only from the
  server process environment.

## 2.2.2 - 2026-07-11

### Added

- SARIF 2.1.0 report generation.
- CycloneDX and SPDX SBOM generation.
- AI-native scanner, cross-file enrichment, attack-chain validation, and
  static executive-summary fallback.
- Baseline suppression, diff-only scanning, trend history, exploit
  intelligence, and output retention.
- FastMCP tools and report/SBOM resources.
- Language-specific code-quality scanner adapters.

### Changed

- Consolidated repository output under `outputs/<repository>/`.
- Pinned external CI actions and scanner installers deliberately.
- Added Python 3.11, 3.12, and 3.13 test coverage.
