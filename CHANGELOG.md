# Changelog

All notable AppSec Galaxy changes are documented here. The project follows
semantic versioning.

## Unreleased

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
