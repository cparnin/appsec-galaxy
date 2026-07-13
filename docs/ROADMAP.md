# AppSec Galaxy - Enhancement Roadmap

Prioritized plan to sharpen AppSec Galaxy into a best-in-class appsec tool.
Written as a handoff so a fresh session can execute without re-discovery.
Read `CLAUDE.md` first (standing rules); this doc is the "what next" on top of it.

## How to work here (read before touching code)

- Gates, all CI-blocking, run before declaring anything done:
  ```bash
  .venv/bin/python -m ruff check src/ mcp/ scripts/ tests/
  .venv/bin/python -m mypy src/appsec_galaxy mcp scripts tests
  PYTHON_DOTENV_DISABLED=1 .venv/bin/python -m pytest tests/ -q
  ```
- Every change ships with tests (`tests/`) and doc updates in the SAME commit
  (`CLAUDE.md`, `README.md`, `AGENTS.md`, `env.example`, `CHANGELOG.md`).
- Never make a live AI call in tests; mock at `_call_ai` / `_get_ai_client`.
- No em dashes anywhere; sparse emojis; concise.
- Commit to `main` directly (admin bypass on); push is fine once gates pass.
- `.env` has `APPSEC_AI_SCAN=false` (no accidental AI spend). Local live tests:
  flip it on, run, flip it back. Two throwaway vuln repos exist:
  `~/repos/vuln_repos/nodejs-goof` and `~/repos/vuln_repos/juice-shop-fork`.

## Current state (as of 2026-07-12, v2.3.0 + follow-ups on main)

- Dual AI provider (OpenAI default, Anthropic opt-in), CLI + web pickers,
  live connection test. All AI goes through `scanners/ai_scanner.py`.
- Report is dark-themed; AI findings lead the detailed-findings block.
- Auto-remediation is syntax-gated: every applied single-line fix passes
  `validate_file_syntax()` and is reverted if it no longer parses. Additive
  findings (Docker missing-USER) are excluded (replace-mode cannot insert).
- Scanners: semgrep (SAST), gitleaks (secrets), trivy (deps + IaC misconfig,
  `APPSEC_TRIVY_SCANNERS`),
  code-quality linters (7 langs), AI scanner, AST cross-file attack chains,
  AI cross-file. EPSS + CISA KEV enrichment (`vuln_intel.py`). SBOM
  (CycloneDX + SPDX). 476 tests.

## Tier 1 - easy buttons (one-flag / ~20-line wins)

### 1a. Wire in Trivy IaC/misconfig (+ license) scanning [DONE 2026-07-13]
- **Where:** `src/appsec_galaxy/scanners/trivy.py`. Two `--scanners vuln`
  call sites (approx lines 98 and 140).
- **Change:** run `--scanners vuln,misconfig` (add `license` if wanted).
- **Real work (not just the flag):** misconfig results come back under a
  different Trivy JSON shape. Each `Results[]` entry can carry
  `Vulnerabilities`, `Misconfigurations`, and `Licenses` arrays. The current
  parser only reads `Vulnerabilities` (`Finding.from_trivy`). Add a
  `Finding.from_trivy_misconfig` (and optionally `_license`) mapping:
  misconfig has `ID`, `Title`, `Severity`, `Description`, `Resolution`,
  `CauseMetadata` (file + start/end line). Map to the canonical Finding.
- **Scope note:** Trivy scans IaC (Terraform, CloudFormation, K8s manifests,
  Dockerfile) and config out of the box. This is the biggest coverage gap;
  "no IaC scanning" is the most visible hole vs best-in-class.
- **Tests:** feed a fixture Trivy JSON with a `Misconfigurations` array,
  assert findings are normalized with file/line + severity. Add a Dockerfile
  or `.tf` fixture under `tests/`.
- **Docs:** README scanner list, CLAUDE.md scanner line, env.example if a new
  toggle is added (e.g. `APPSEC_TRIVY_SCANNERS`).

### 1b. Make SARIF first-class for GitHub Code Scanning [DONE 2026-07-13]
- **Where:** `src/appsec_galaxy/reporting/sarif.py` (rules dict ~L47, result
  object ~L56-78).
- **Add two things GitHub needs:**
  - `security-severity` (string number "0.0".."10.0") in each rule's
    `properties` (GitHub's Security tab reads this, not SARIF `level`). Map
    critical=9.5, high=8.0, medium=5.5, low=3.0.
  - `partialFingerprints` on each result (e.g.
    `{"primaryLocationLineHash": <sha256 of ruleId+relpath+snippet>}`) so
    GitHub dedups findings across runs and tracks fix/reopen lifecycle.
  - Optional: `helpUri` per rule when the source tool provides one.
- **Tests:** assert emitted SARIF has `security-severity` and
  `partialFingerprints`; validate against the SARIF 2.1.0 shape already used.
- **Why:** you already emit SARIF; without these fields it renders as
  second-class and re-alerts every run.

### 1c. Semgrep `--metrics off` (privacy + reproducibility) [DONE 2026-07-13]
- **Where:** `src/appsec_galaxy/scanners/semgrep.py`, the `cmd.extend([...])`
  around L82.
- **Change:** add `"--metrics=off"`. `--config auto` currently sends scan
  telemetry to Semgrep's registry by default; a tool scanning private/client
  code should not. One flag. (See Tier 3 for pinning the ruleset too.)
- **Tests:** assert the constructed command includes `--metrics=off`
  (there is a semgrep command-construction test pattern to follow).

## Tier 2 - the differentiators (medium effort, high payoff)

### 2a. Wire reachability INTO CVE prioritization (flagship item) [DONE 2026-07-13]
- **The data already exists, it is just not connected:**
  - `dependency_analyzer.py` computes per-dependency `import_sites`,
    `unique_apis_used`, and `remediation_strategy`
    (`keep|upgrade|inline|replace|remove`) - i.e. whether a dep is actually
    imported/called.
  - `vuln_intel.py` computes `epss_score`, `in_kev`, and `exploit_priority`
    (`urgent`|`high`|`normal`) per CVE.
- **Do:** in the enrichment path (`enhanced_analyzer.py`, where trivy findings
  get cross-file/intel enrichment), join a Trivy CVE's `PkgName` to its
  `DependencyUsage`, then combine signals into a single priority:
  - reachable/called dep + KEV or high EPSS -> escalate (top of report).
  - unused / dev-only / not-imported dep -> de-escalate (fold or mark
    "reachability: not imported").
- **Gotcha:** package-name matching across sources (Trivy `PkgName` vs the
  dependency_analyzer's package identity, incl. ecosystem prefixes/scopes).
  Build a normalizer and unit-test it on npm scoped names + python extras.
- **Surface it:** show the reachability verdict on each dependency finding in
  the HTML report and SARIF properties. Currently reachability is computed but
  not shown in `reporting/html.py`.
- **Why this is the flagship:** exploit-probability AND reachability ranking is
  what separates elite tools from noisy ones. Best noise-reduction ROI here.

### 2b. Secret confidence / validation [offline layer DONE 2026-07-13; live validation deferred]
- **Where:** `scanners/gitleaks.py` normalization path.
- **Add a confidence layer** (no network by default):
  - Shannon entropy of the captured secret.
  - Known-placeholder / test-fixture patterns (`your-...-here`, `example`,
    `xxxx`, all-same-char) -> low confidence.
  - Surface `confidence` on the finding; let the report sort/collapse
    low-confidence secrets.
- **Optional opt-in live validation** (env-gated, off by default; network):
  a few high-value providers only (AWS STS `GetCallerIdentity`, GitHub token
  `/user`). Never log the secret value. This is the TruffleHog-style "is it
  live" check that kills false-positive fatigue.
- **Tests:** entropy + placeholder classification are pure functions - unit
  test them. Mock any network for the validation path.

## Tier 3 - polish (defer, do after Tier 1-2)

### 3a. AI scan: prefer entry points instead of a flat top-50
- **Where:** `ai_scanner.py::_select_security_files` (relevance sort + the
  `APPSEC_AI_SCAN_MAX_FILES` cap; the "skipped N candidates" warning already
  exists). On juice-shop it analyzed 50 of ~600 files.
- **Do:** bias selection toward `cross_file_analyzer` entry points / sinks and,
  in PR mode, honor `APPSEC_DIFF_ONLY` so the AI budget goes to changed +
  reachable code rather than a flat relevance sort. Keep the cap as the cost
  lever.

### 3b. Pin the Semgrep ruleset (reproducibility)
- **Recommended: yes.** `--config auto` is non-reproducible (rules change
  under you) and needs network. Bundle a pinned ruleset (vendored or a pinned
  registry ref) so scans are deterministic and offline-capable. Pairs with
  1c. Keep `auto` behind an opt-in flag if you want "latest" on demand.

## Sequencing suggestion

Tier 1 in one sitting (coverage + integration jump), commit each item
separately with tests. Then 2a as the flagship (highest signal), then 2b.
Tier 3 when convenient. Do not widen scope (no new bespoke scanners, no SaaS
dashboard) - deepen the orchestrate + synthesize + reachability thesis.
