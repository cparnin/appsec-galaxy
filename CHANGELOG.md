# Changelog

All notable AppSec Galaxy changes are documented here. The project follows
semantic versioning.

## Unreleased

## [2.7.0] - 2026-09-04

A full review of the application: six parallel reviews (core orchestration,
scanners and reporting, the AI boundary and remediation, MCP and CI, docs,
tests), then every verified finding fixed with a regression test. The
headline results: gitleaks no longer reports a clean scan on a non-git
directory, three code-quality linters that could never return a finding
were fixed or removed, the GitHub Action no longer crashes on its own
default input, and the executive summary's numbers agree with each other.

### Security

- MCP scans run the scanner with Python's safe-path flag (`-P`). `python -m`
  put the scanned repo's directory first on `sys.path`, so a hostile repo
  shipping a `dotenv/` package ran its code inside the scanner process with
  the provider keys in its environment.
- The AI file selector skips symlinks and anything that resolves outside
  the repo, and a model-supplied finding path can no longer be opened
  outside the repo. A repo could symlink `auth_config.py` to
  `~/.aws/credentials` and have it sent to the AI provider.
- Auto-remediation stages only the files it changed (`git add -- <files>`
  plus regenerated lockfiles) instead of `git add .`, which swept an
  untracked `.env` or leftover backup into the pull request.
- Code-quality linters never load the scanned repo's own configuration:
  the bundled config wins, pylint gets `--rcfile=/dev/null`, ESLint runs
  with `--no-config-lookup` / `--no-eslintrc`. Linter configs execute code
  (pylint `init-hook`, JavaScript ESLint configs, RuboCop `require:`).
  Clippy and PHPStan are removed: both execute repo code by design (cargo
  build scripts, the PHP autoloader) and, because their JSON went to stdout
  that the base class discarded, neither had ever produced a finding.
- The MCP scan-root allowlist no longer includes the home directory and
  the server's working directory by default (defaults are `~/repos` and
  `~/projects`), and fuzzy repo matching skips dotfiles, so a client cannot
  reach `~/.ssh` or `~/.aws` by name.
- The Action and self-scan artifacts exclude `raw/gitleaks.json`, which
  carries plaintext secret values; self-scan retention drops to 30 days.
- `/scan` rejects a non-boolean `auto_fix` (the string `"false"` was truthy
  and turned on the commit/push/PR path), an unknown `scan_level`, an
  invalid `auto_fix_mode`, and a non-list `selected_tools`.
- Gitleaks no longer logs raw report content (secret values) on a JSON
  parse failure.

### Fixed

- Gitleaks reported a clean scan on any non-git directory: without
  `--no-git` it failed to open the "repository" and wrote an empty report.
  It now passes `--no-git` when `.git` is absent, and any non-zero exit is
  treated as a failure (with `--exit-code 0`, findings never exit 1).
- The bundled gitleaks config's custom `private-key` and `pem-private-key`
  rules replaced upstream's rule of the same id and lost OpenSSH/PGP key
  detection. Both are removed, along with seven custom rules that
  duplicated an upstream shape under a different id and made every AWS,
  GitHub, Slack, Google, Stripe, SendGrid, and Twilio secret report twice.
- golangci-lint and SwiftLint print their JSON report to stdout; the
  quality-scanner base now saves stdout for tools that declare
  `reads_stdout`, so both return findings. golangci-lint v2 (new config
  schema and output flags) is supported alongside v1.
- Checkstyle exits with its violation count; the base class treated 2+ as
  a crash and dropped every finding. Tools now declare their own fatal
  exit codes.
- One ESLint parse error (`ruleId: null`) raised inside the parser and
  dropped every ESLint finding. `--ext` is no longer passed to ESLint 9,
  which rejects it under flat config.
- One post-scan pipeline for all three modes. `finalize_scan()` in
  main.py now runs cross-file enhancement, dependency reachability, the
  HTML report, the PR summary, and the SBOM for CLI auto, CLI interactive,
  and web mode. The three pasted copies had drifted: the web report had no
  language list, web auto-fix acted on unenhanced findings, and a clean
  CLI scan wrote no report at all. The AI cross-file layer also ran twice
  per CLI scan (once for findings, again for the PR summary); it now runs
  once through `run_cross_file_pipeline()`.
- The interactive CLI validates and resolves the selected repository path
  like the other modes; a relative path defeated baseline globs and
  diff-only matching (every semgrep finding filtered out).
- `APPSEC_SCAN_LEVEL` is validated once (`resolve_scan_level()`) and the
  sanitized value is what runs. An invalid value previously logged a
  fallback and then passed the raw value to semgrep, whose filter matched
  nothing.
- The web server runs one scan at a time (per-request settings travel
  through the process environment, so concurrent scans read each other's
  provider and tier), validates its own configuration before a request
  mutates the environment, reports the real package version from
  `/health`, and sends a valid HTTP date in `Last-Modified`.
- Auto-fix mode is narrowed to what there is to fix in every mode; mode 1
  with only dependency findings used to print "Auto-remediation complete"
  having done nothing.
- Fork detection compares the PR head repository to the repository running
  the workflow (in `action.yml` and `is_untrusted_pr_context`) instead of
  `head.repo.fork`, which is true for every PR in a project that was itself
  forked from a template, and covers `pull_request_target`.
- The Action's `critical-findings` / `high-findings` outputs include Trivy
  CVEs and misconfigurations by severity; three critical CVEs with no
  semgrep findings produced an "All Clear" PR comment. The client
  workflow's comment now reports a failed or timed-out scan instead of
  "All Clear" with empty counts.
- Usage analytics are written under the outputs directory, never the
  current working directory (which could be the scanned repo, where
  `git add` would have committed them).
- Web UI: a failed scan request no longer throws inside the error handler
  (the progress panel had no "overall" element), progress timers are
  cancelled between scans, and the remediation phase no longer accumulates
  one extra entry per scan. Inline `onclick` handlers are gone.
- `SECURITY_ENGINEER_HOURLY_RATE` is finally used (the report hardcoded
  $150). `REPO_SEARCH_PATHS` is colon-separated in every mode (the web UI
  split on commas, the CLI and MCP on colons).

- Cross-file attack chains were fabricated. Import resolution matched
  `module in absolute_path`, so `import os` wired a file to anything under
  a checkout path containing "os" (every path under `~/repos`, for
  instance), and the AI layer then paid to validate the phantom chains.
  Modules now resolve to an exact file (relative, dotted, and path-style
  imports, including Python's `from . import x`), the analyzer keys
  everything by repo-relative path, and directory pruning matches
  directory names instead of path substrings (a checkout under
  `.../devenv/...` used to analyze zero files).
- Finding-to-chain correlation goes through one `to_repo_relative()`
  helper, so a semgrep finding (absolute path) and an AI finding
  (relative) match the same chain. The cross-file path normalizer no
  longer uses `lstrip('./')`, which turned `.env` into `env` and
  `.github/x` into `github/x`.
- One malformed AI finding no longer discards the whole scan. Model output
  is coerced before use (`"42"` for a line, `"high"` for a confidence,
  `null` for a type), so a single bad field cannot raise past the batch.
- The verification pass matches confirmed findings by id instead of an
  exact (file, line, type) tuple the model re-types; a reply saying
  `"./app.py"`, `"42"`, or `"sql injection"` used to drop a confirmed
  finding as a false positive.
- AI-versus-semgrep deduplication works at all: both sides are normalized
  to repo-relative paths and bare CWE ids first (semgrep emits absolute
  paths and "CWE-89: Improper ..." strings).
- Preflight probes the model the scan will actually use; it probed the
  cheapest model, so a retired standard or deep model passed preflight and
  every batch then failed, which reads as a clean repository.
- Anthropic token accounting: `usage.input_tokens` excludes cache reads
  and writes, so cached calls were under-billed (the discount was applied
  twice) and cache writes were never charged. Both are now recorded, and
  the USD cap covers cross-file analysis and auto-fix calls too, not just
  the file scanner.
- `AutoRemediator` builds its provider client lazily, so dependency-only
  auto-fix (which makes no AI calls) no longer requires an API key.
- Trivy's multi-version `FixedVersion` ("2.2.28, 3.2.13") is resolved to a
  single version; the raw string was written into manifests, producing
  uninstallable requirements.
- Trivy vendor-directory fallback re-roots its result paths under the
  vendor directory, so baseline suppression, diff scoping, SARIF, and
  history see paths that exist at the repo root.
- Report and summary key drift: the executive summary digest reads
  gitleaks' `Description` and trivy's description (secrets were counted as
  "unknown" and every trivy row said "No description"), secrets render
  with their real severity instead of an UNKNOWN/low badge, the AI attack
  chain validation block renders (its AI fields were dropped in
  projection), and dependency health reads `pkg_name`.
- Severity comparisons in the enhanced analyzer compared against uppercase
  values that the pipeline never produces, so the critical count was
  always zero.
- SBOM generation has a 300s timeout (a hung syft hung the request) and no
  longer tries to enrich from a CWD-relative directory that does not exist.
- The exploit-intel cache moved out of a fixed shared temp path into the
  per-user cache directory.

### Tests

- The suite is split by area into `test_scanners.py`,
  `test_dependency_analysis.py`, `test_ai_analysis.py`,
  `test_remediation.py`, `test_pipeline_cli.py`, `test_reporting.py`, and
  `test_interfaces.py` (the old 5,600-line `test_appsec_galaxy.py` is
  gone); `tests/README.md` maps each file to what it covers.
- Tests that asserted against logic pasted into the test file now drive
  the real functions (`validate_attack_chains`,
  `run_cross_file_pipeline`), and the AI-disabled and privacy-tier tests
  fail loudly if a provider client is built instead of passing because no
  key happens to be configured.
- No test makes a network request (the dependency integration tests were
  issuing registry lookups), `conftest.py` disables dotenv loading for the
  whole session so a reimport cannot pull in real keys, the privacy-tier
  picker test no longer leaks its env var, and 12 unused fixtures are gone.
- New coverage for remediation safety gates (protected files, secret
  findings, path confinement) and web security (API-key enforcement, the
  report allowlist, directory-browsing policy).

### Documentation

- Corrected every claim the audit found stale: max output tokens in
  `ARCHITECTURE.md` (4096/4096/8192 to 8192/16384/32768), "draft pull
  request" (no PR is a draft), 90-day artifact retention in
  `clients/SETUP.md` (30), the client workflow's "default settings" block
  (it showed OpenAI wiring the workflow does not use), `mcp/README.md`
  still presenting OpenAI as the default provider, the claim that the
  repository ships `.codex/config.toml` (it is git-ignored), and the
  suggestion that an MCP resource URI can take a path (the template
  matches one segment).
- `ARCHITECTURE.md` is now the canonical security-invariant list and
  carries the complete package layout; `CLAUDE.md` and `AGENTS.md` point
  to it. Gate commands live in `CLAUDE.md` alone, and the model/pricing
  tables name `ai_scanner.py` as their source instead of repeating values.
- `env.example` lost the dead `LOG_LEVEL` line, changelog-style commentary
  about removed variables, wrong `src/` paths, and a
  directory-browsing default that contradicted its own warning;
  `APPSEC_AUTO_FIX_DELAY` is documented with its real default (0) and
  meaning (between fixes, not before the first).
- `docs/ROADMAP.md` is rewritten as a short historical record: every item
  shipped, and it carried stale counts, a personal filesystem path, and
  workflow rules that contradicted `CLAUDE.md`.

### Removed

- `requirements-web.txt`, which nothing referenced (the `web` extra in
  `pyproject.toml` covers it), and the test-only packages in
  `requirements.txt`, which the Action runner installed on every client
  run. A test now pins requirements.txt to pyproject's runtime list.
- Dead SBOM code (`generate_sbom_formats`, the SPDX/CycloneDX converters,
  the Snyk enrichment block) and the redundant second dependency-manifest
  walk in the Trivy scanner.
- `APPSEC_TOOLS`: parsed into a value nothing read; the CLI picker and the
  web checkboxes select tools. `LOG_LEVEL` (never read) and `FLASK_DEBUG`
  (`APPSEC_DEBUG` now also enables the Flask debugger). The dead
  "minimal output" logging block in main.py that targeted logger names
  that do not exist. `action.yml` no longer forces `APPSEC_DEBUG` and
  `APPSEC_LOG_LEVEL` on, so a caller's `env:` can set them.
- `APPSEC_AI_SCAN_MAX_COST=''` (what the GitHub Action exports when the
  input is left blank) failed pydantic float parsing at startup, so every
  client run of v2.6.3 crashed before scanning. Empty env vars now count
  as unset for all `APPSEC_*` settings.

- The bundled gitleaks config now extends the upstream default ruleset
  (`[extend] useDefault = true`), adding 150+ maintained provider rules on
  top of the 20 hand-written ones. Detection was previously frozen at the
  formats written by hand, so any credential prefix a provider introduced
  or rotated was silently undetectable. Verified: an npm access token that
  the old config missed is now caught, with no new findings on this repo
  (the five re-matched fixture/demo lines are suppressed by fingerprint in
  `.gitleaksignore`). Deliberately did **not** add a path allowlist to the
  bundled config, since it applies to scanned repositories and would hide
  real secrets in someone else's tree.
- Gitleaks findings no longer carry the plaintext credential past the
  `Finding` boundary. `Secret` and `Match` are stripped in
  `Finding.from_gitleaks`, so the secret value no longer reaches the web
  `/scan` JSON response, the HTML report, or any AI prompt. Confidence
  classification is unaffected (it reads the raw record first), and the
  verbatim value still exists only in `outputs/<repo>/raw/` (gitignored).
  The MCP surface already redacted this; the web surface had diverged.
- Fixed DOM XSS sinks in the web UI. The repository browser built
  `onclick="browseInto('<path>')"` by string concatenation with an escaper
  that handled `\` and `'` but not `"`, so a directory named
  `x" onmouseover="..."` broke out of the attribute. The browser list, the
  results-panel repo name/path, and server error text are now built with
  DOM APIs and `textContent`, with no inline event handlers anywhere.
- Added baseline security headers to every web response (CSP,
  `X-Frame-Options: DENY`, `X-Content-Type-Options`, `Referrer-Policy`) as
  defense in depth behind Jinja autoescaping, since the report rendered
  from hostile scanned repos is served from the app's own origin.
- Added a DNS-rebinding guard: when bound to loopback, requests carrying a
  non-loopback `Host` header are rejected. An intentional `0.0.0.0`
  deployment is unaffected.
- Hardened argument handling against untrusted scanner output:
  `validate_package_name` now rejects a leading hyphen, `go get` and macOS
  `open` take `--`, and pylint's file list is preceded by `--` so a file
  named `--rcfile=evil.cfg` cannot load an arbitrary plugin.
- `_secure_file_path` now compares the repo boundary with a trailing
  separator, so a symlink resolving to a sibling directory that shares the
  repo's prefix (`/repo-evil` vs `/repo`) is rejected.
- Package names are percent-encoded before going into registry URLs
  (structural characters preserved for npm scopes, Go module paths, and
  Maven `groupId:artifactId`).

### Fixed

- Interactive-CLI reports over-counted vulnerable dependencies. The
  interactive summary counted every trivy finding as a dependency CVE,
  including IaC misconfigurations, and omitted the misconfiguration line
  entirely, so it disagreed with the auto/CI-mode summary for the same
  repository. Both paths now compute identical counts.
- The AI scanner now preflights the provider before sending any batch. A
  retired model ID or revoked key previously failed inside every batch and
  returned an empty findings list, which is indistinguishable from a clean
  repository; it now stops with the explicit error naming the cause.
- The dependency-pin test asserts the shape of the `openai` constraint
  (floor and ceiling) instead of the exact string, so Dependabot's
  ceiling bump (#7) no longer fails the suite.
- `run_tests.sh` runs the whole suite instead of a single file, matching
  the CI gate (it silently skipped the two AI test modules).
- Gitleaks no longer reports every SHA-1 hash as a Sourcegraph token. The
  upstream `sourcegraph-access-token` rule (inherited since the ruleset
  extension above) accepts any bare 40-hex string when a file mentions
  "sourcegraph", which turned one repository's committed-then-deleted SBOM
  files into 610 false "secrets" from git history. The bundled config now
  overrides that rule id with a regex that requires the real `sgp_` token
  prefixes; verified against the real binary (636 to 26 on that repo, the
  remaining 26 being example keys in docs and test fixtures).
- Executive summary numbers now agree with each other. The HTML report's
  Critical/High tiles and the "manual hours" estimate counted code quality
  findings (a pylint "error" showed as a high-severity security issue,
  4 in the tile vs 1 in the text), and the risk badge used a different
  formula from the summary text (High Risk badge above a Medium Risk
  line). `compute_summary_stats()` / `risk_assessment()` /
  `build_fallback_summary()` in `reporting/ai_summary.py` are now the one
  source for the tiles, the badge, and the fallback summary text, which
  was previously pasted into `main.py` twice and `web_app.py` once; the
  web result cards (`scan_summary`) and the CLI results print use it too.
  Critical/High count security findings only; any critical finding or
  any detected secret is High Risk, any high finding is Medium.
- The web server picks up a provider key rotated in `.env` without a
  restart. It loaded `.env` once at startup, so replacing a revoked
  `ANTHROPIC_API_KEY` kept failing the pre-scan connection test with
  "rejected the API key" even though the new key was valid. `/scan` and
  `/config` now re-read changed provider keys from `.env` (mtime-gated;
  blank and placeholder values are ignored, and a shell-exported key still
  wins until `.env` is edited) and drop the cached SDK client.

### Changed

- Anthropic is now the default AI provider: blank or unset `AI_PROVIDER`
  resolves to `anthropic` across CLI, web, GitHub Action (`ai-provider`
  input default), and MCP. Set `AI_PROVIDER=openai` to keep OpenAI. The
  depth model mapping is unchanged (quick=claude-haiku-4-5,
  standard=claude-sonnet-5, deep=claude-opus-4-8). `env.example`,
  `mcp/mcp_env.example`, and the drop-in client workflow now lead with
  `ANTHROPIC_API_KEY`.
- The self-scan workflow is rule-based only: removed the weekly scheduled
  AI deep scan and all provider keys from CI, so the workflow makes no AI
  API calls and costs nothing. Rule-based scanners still run on every
  push and PR.
- Future-proofing for long unattended periods: the Action now uses Node 22
  (18 is EOL and current ESLint requires >= 20, which would have silently
  dropped all JS/TS quality findings) and pins the pylint/eslint majors;
  `ruff` and `mypy` gained upper bounds so a new lint rule in a minor
  release cannot turn CI red with no code change.
- Refreshed the OpenAI rows of `MODEL_PRICING` for the 2026-07-30 price
  cut (gpt-5.6-luna $0.20/$1.20, gpt-5.6-terra $2/$12 per 1M tokens), so
  printed cost estimates match current list prices.

## [2.6.3] - 2026-07-17

### Security

- Auto-remediation now confines every dependency-fix file operation to the
  scanned repo. `_fix_dependency` built its target with
  `os.path.join(repo_path, finding['path'])` and `can_remediate_dependency`
  gated only on a substring match, so a crafted trivy finding path like
  `../../../etc/x/requirements.txt` (findings are untrusted scanner output)
  could make the tool write a `.backup` or rewrite a manifest-named file
  outside the repo when dependency auto-fix was enabled. Now the resolved
  path must sit under the repo root or the fix is skipped. `apply_fix` (the
  SAST write sink) gained the same realpath confinement defensively; it was
  already gated upstream by `_secure_file_path`, but now validates at its
  own sink. Surfaced by CodeQL `py/path-injection` triage. Regression tests
  added for traversal and absolute-path escapes.
- The Action installs Syft via a SHA-pinned `anchore/sbom-action/download-syft`
  step instead of `curl -sSfL ... | sh`, which executed unpinned fetched
  bytes. Matches the pinning of every other setup step. (AppSec Galaxy's own
  `gha-curl-pipe-shell` finding.)

## [2.6.2] - 2026-07-17

### Fixed

- SARIF `partialFingerprints` now uses a tool-namespaced key
  (`appsecGalaxy/v1`) instead of `primaryLocationLineHash`, which GitHub
  computes itself with different semantics; every upload warned about
  inconsistent fingerprints and alert dedup could churn.
- Self-scan Security-tab noise: the CI history scan (fetch-depth 0)
  surfaced fake demo-app secrets inside raw scan outputs committed before
  `outputs/` was gitignored, plus test fixtures at historical commits.
  Suppressed with commit-anchored fingerprints in `.gitleaksignore` (git
  mode ignores the dir-mode entries) and `tests/*` / `outputs/*` baseline
  globs. A remediation doc example in `enhanced_analyzer.py` now uses the
  allowlisted `your-api-key-here` placeholder instead of tripping the
  generic-secret rule.

## [2.6.1] - 2026-07-17

### Fixed

- Pip-installed runs (the self-scan, the GitHub Action) resolved resource
  paths relative to the installed package, so scan outputs were written
  next to site-packages where CI steps never looked: the artifact upload
  was empty, the new SARIF upload found nothing, the fail-on-critical
  gate read an empty directory and passed trivially, and the Action's
  count outputs reported zero. `project_paths` now falls back to the
  working directory when not running from a source checkout. Source
  checkouts (CLI, web, MCP, dev) are unchanged.

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
