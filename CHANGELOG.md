# Changelog

All notable AppSec Galaxy changes are documented here. The project follows
semantic versioning.

## Unreleased

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
  `ANTHROPIC_API_KEY`); OpenAI remains the default. The interactive CLI now
  includes a provider picker with a live connection test.

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
