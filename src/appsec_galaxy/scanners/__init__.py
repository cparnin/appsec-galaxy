"""Security scanners package for AppSec Galaxy.

Contains:
- semgrep.py: SAST scanning (rule-based)
- gitleaks.py: Secrets scanning (regex + entropy)
- trivy.py: Software Composition Analysis (CVE database)
- ai_scanner.py: AI-native security analysis, Anthropic or OpenAI (logic errors, auth flaws)
- quality_scanner_base.py + eslint/pylint/checkstyle/golangci_lint/rubocop/swiftlint:
  code-quality linters (always run with the bundled config, never the repo's own)
"""
