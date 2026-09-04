# AppSec Galaxy architecture

AppSec Galaxy is a local-first application security pipeline. Deterministic
scanners produce the primary evidence; optional AI analysis (OpenAI or Anthropic) adds semantic
and cross-file context without becoming a prerequisite for rule-based results.

## Pipeline

```mermaid
flowchart LR
    A["Repository selection and validation"] --> B["Rule-based scanners"]
    B --> C["Normalize findings"]
    C --> D["Baseline and diff filters"]
    D --> E["Cross-file analysis"]
    E --> F["Optional AI enrichment"]
    F --> G["HTML, SARIF, SBOM, history"]
    G --> H["Optional constrained remediation"]
```

1. CLI, web, Action, or MCP validates the repository boundary.
2. Semgrep, Gitleaks, Trivy, and available quality scanners run without a
   shell and emit their native result shapes.
3. Finding helpers normalize paths, rule IDs, severity, messages, and lines.
4. `.appsec-galaxy-ignore` and PR-diff scoping filter findings. Both fail open.
5. Structural cross-file analysis traces entry points, sinks, and attack paths.
6. If enabled, the shared AI boundary validates or enriches results.
7. Reports, SBOMs, and trend history are written under the repository output.
8. Remediation may propose and apply safe single-line replacements before
   creating a pull request.

## Package layout

```text
src/appsec_galaxy/
├── main.py                  # CLI, scan orchestration, finalize_scan pipeline
├── web_app.py               # local Flask interface
├── config.py                # constants + pydantic-settings validation
├── finding.py               # canonical Finding dataclass (scanner boundary)
├── scanners/                # security and quality scanner adapters
├── ai_cross_file.py         # optional semantic cross-file enrichment
├── cross_file_analyzer.py   # deterministic cross-file analysis
├── enhanced_analyzer.py     # cross-file enhancement + report pipeline
├── dependency_analyzer.py   # dependency code-path/reachability analysis
├── package_registry.py      # registry lookups for dependency health
├── vuln_intel.py            # EPSS / CISA-KEV enrichment and CVE priority
├── sbom_generator.py        # CycloneDX + SPDX SBOMs (syft)
├── auto_remediation/        # safety checks, fixes, and PR workflow
├── reporting/               # HTML, SARIF, and summary generation
├── scan_filters.py          # baseline and diff filters
├── scan_history.py          # trend history (new vs fixed per scan)
├── path_utils.py            # repository output paths and retention
├── project_paths.py         # checkout resource locations
└── templates/index.html     # web UI (single file)
```

Scanner configuration lives under `configs/`. The MCP server, CI gates, and
client workflow remain outside the import package so their operational
boundaries stay explicit.

## Output layout

`project_paths.py` anchors bundled resources and outputs to the checkout root.
`path_utils.get_output_path()` assigns one canonical directory per scanned
repository:

```text
outputs/<repository>/
├── raw/
│   ├── semgrep.json
│   ├── gitleaks.json
│   ├── trivy-sca.json
│   ├── ai_scan.json            # when the AI scanner ran
│   ├── pylint.json             # and other code-quality linters
│   └── dependency-health.json
├── sbom/
│   ├── sbom.cyclonedx.json
│   └── sbom.spdx.json
├── report.html
├── report.sarif
└── history.json
```

The current scan replaces older artifacts while `history.json` survives for
trend comparison. Retention periodically purges inactive repository output
directories. Raw output may contain sensitive material and is Git-ignored.

## AI call boundary

`scanners/ai_scanner.py` owns provider validation, model selection, the cached
SDK wrapper, provider API requests (OpenAI Responses API or Anthropic Messages
API), retry policy, usage accounting, and cost estimation. Other modules reuse
`_get_ai_client()`, `_get_model_id()`, and `_call_ai()` rather than
constructing SDK clients. `test_ai_connection()` performs a minimal live call
so the CLI can validate a provider before starting work.

The call contract keeps stable instructions separate (OpenAI `instructions`,
Anthropic `system`) from dynamic code or finding data. Only transient network,
timeout, rate-limit, and server failures are retried, for at most three
attempts. Missing or malformed verification output preserves original
findings. Cross-file and report-summary wrappers preserve deterministic/static
results when optional AI work fails.

Default depth mapping:

| Depth | OpenAI | Anthropic | Max output tokens |
| --- | --- | --- | ---: |
| quick | `gpt-5.6-luna` | `claude-haiku-4-5` | 8192 |
| standard | `gpt-5.6-terra` | `claude-sonnet-5` | 16384 |
| deep | `gpt-5.6-sol` | `claude-opus-4-8` | 32768 |

`DEPTH_MODEL_MAP`, `DEPTH_MAX_TOKENS`, and `MODEL_PRICING` in
`scanners/ai_scanner.py` are the source of truth for this table.

## Remediation boundary

Auto-remediation operates only on supported findings and text files. It rejects
secrets, protected paths, traversal, oversized/binary input, invalid package or
version strings, multi-line model output, and replacements over the configured
limit. A replacement inherits the original line indentation. Git and package
manager subprocesses use argument arrays and validated inputs.

AI output is a proposal, not trusted code. Generated pull requests remain
review artifacts and must pass the target repository's tests before merge.

## MCP boundary

`mcp/appsec_galaxy_mcp_server.py` provides a lazy `AppSecGalaxyMCPCore`.
Importing or initializing it locates the checkout and output utilities but does
not construct an AI client. Tool calls resolve and validate repositories at
the boundary, then invoke package entrypoints with the server process
environment.

The server identity is `appsec-galaxy`. Its 16 tools cover scanning,
remediation, reports, SBOMs, cross-file/business analysis, per-tool findings,
health, and dependency analysis. Four resources expose report and SBOM
artifacts through `appsec-galaxy://{repo}/...` templates.

## Scanner extension pattern

New scanner adapters should:

1. validate the external executable and repository path;
2. use `subprocess.run([...], shell=False)` with a bounded timeout;
3. write raw output only under the supplied output directory;
4. normalize findings without mutating another scanner's schema;
5. fail gracefully when an optional tool is unavailable;
6. include focused parser, timeout, missing-tool, and malicious-input tests;
7. register in orchestration and update public documentation.

Quality scanners extend `QualityScannerBase` when possible so bundled config
fallback and finding normalization remain consistent.

## Security invariants

This is the canonical list. `CLAUDE.md` and `AGENTS.md` summarize it for
day-to-day work; when they disagree, this section wins.

- Scanned files, filenames, scanner output, findings, and model output are
  untrusted.
- Paths are resolved and checked against repository boundaries before access;
  symlinks out of the repository are never read.
- Scanned-repository code never executes: subprocesses use argument arrays
  with `shell=False`, linters run with bundled configuration rather than the
  repository's own, the MCP scanner subprocess runs with Python's safe-path
  flag, and lockfile regeneration disables install scripts.
- Secrets are never persisted in configuration, logs, history, examples, or
  MCP client settings, and raw secret output is never published as a CI
  artifact.
- XML from scanned repositories is parsed with hardened libraries.
- HTML rendering autoescapes finding content; the web UI builds DOM nodes
  with `textContent` and uses no inline event handlers.
- Baseline/diff failures and AI verification failures never hide findings; a
  tool that fails is reported as a failure, never as zero findings.
- Auto-remediation stages only the files it changed, is forced off on fork
  pull requests, and reverts any fix that no longer parses.
- Output stays local, ignored, and retention-controlled.
- MCP initialization is offline; model access happens only in explicit AI
  features.
- CI uses pinned third-party actions and blocking test/lint/type gates.

## Key decisions

- Source-layout packaging prevents checkout-relative import ambiguity.
- One shared AI boundary supports two providers (Anthropic default, OpenAI
  opt-in), keeping configuration and retry logic in a single module.
- Rule-based results are authoritative; AI enrichment is optional and
  failure-tolerant.
- One current output per repository keeps MCP and CI artifact discovery
  deterministic.
- The identity migration is a cutover: old names, aliases, resource schemes,
  baseline filenames, and credential paths are not compatibility surfaces.
