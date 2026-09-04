# Roadmap (historical record)

Every item planned here shipped. It is kept as a record of why the
2026-07 features exist; `CHANGELOG.md` is the authoritative history, and
the working rules live in `CLAUDE.md` and `AGENTS.md`.

## Tier 1: easy buttons

- **Trivy IaC and misconfiguration scanning** (`APPSEC_TRIVY_SCANNERS`,
  default `vuln,misconfig`). Terraform, CloudFormation, Kubernetes
  manifests, and Dockerfiles are scanned alongside dependency CVEs.
- **First-class SARIF for GitHub code scanning**, with a stable
  fingerprint (`appsecGalaxy/v1`) so alerts survive line shifts.
- **Semgrep telemetry off** (`--metrics off`) for privacy and
  reproducibility.

## Tier 2: differentiators

- **Reachability folded into CVE priority.** A CVE in a package the code
  actually imports escalates; one that is never imported de-escalates.
  Implemented in `dependency_analyzer.py` and `vuln_intel.py`.
- **Offline secret confidence classification.** Live credential
  validation was deliberately not built: it would send candidate secrets
  to third parties.

## Tier 3: polish

- **AI scan file selection prefers entry points** over a flat top-N list.
- **Pinned Semgrep rulesets** (`APPSEC_SEMGREP_CONFIG`, default
  `p/default`); `auto` restores dynamic per-repo selection.

## Ideas not pursued

- Live secret validation (sends secrets to third-party APIs).
- A hosted multi-tenant service: this is a local-first scanner, and the
  threat model assumes scanned repositories are hostile input.
