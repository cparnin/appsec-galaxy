# AppSec Galaxy Setup

AI-powered security scanner for any programming language. Detects vulnerabilities and can create fix PRs.

## Quick Setup (3 steps)

### 1. Add Workflow
```bash
cp security-scan.yml .github/workflows/
```

### 2. Configure Credentials

Go to **Settings → Secrets and variables → Actions** and add one secret:

- `ANTHROPIC_API_KEY` - get one at https://console.anthropic.com/settings/keys
  (or use OpenAI: set `ai-provider: 'openai'` in the workflow and add an
  `OPENAI_API_KEY` secret from https://platform.openai.com/api-keys)

That's it. The workflow template is already wired to use it.

### 3. Commit and Push
```bash
git add .github/workflows/security-scan.yml
git commit -m "Add AppSec Galaxy security scanning"
git push
```

## What You Get

- **Automated scans** on every PR
- **AI-generated fixes** for code vulnerabilities
- **Separate PRs** for code fixes vs dependency updates
- **HTML reports** with business impact analysis
- **Auto SBOM** (CycloneDX and SPDX) for compliance
- **Artifacts** - reports and SBOM files (30-day retention; raw secret
  output is deliberately excluded)

## Configuration Options

What `security-scan.yml` sets, and what you can add:
```yaml
with:
  anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}   # or openai-api-key with ai-provider: openai
  # scan-level: 'critical-high'  # default; 'all' includes medium and low
  # auto-fix: 'true'             # default; opens fix PRs on pushes and same-repo PRs
  # auto-fix-mode: '3'           # 1=SAST+secrets, 2=dependencies, 3=both, 4=skip
                               # (unset = chosen from what the scan found)
  # ai-scan: 'true'            # AI deep analysis (default false; needs an API key)
  # ai-scan-depth: 'standard'  # quick, standard, or deep
  # ai-scan-tier: '3'          # 1 no AI calls, 2 metadata only, 3 full source
  # ai-scan-max-cost: '1.00'   # hard USD ceiling per run
  # fail-on-critical: 'false'    # default; 'true' fails the build on critical findings

# Note: Code quality findings are ALWAYS shown regardless of scan-level
# Note: Auto-fix is forced off on FORK pull requests only. A fork PR is
#       outside code (it can supply anything) and remediation
#       commits/pushes/opens PRs, so fork PRs are scan-and-comment only.
#       Your own same-repo PRs and pushes create fix PRs normally.
```

## Supported Languages & Frameworks

**Languages**: JavaScript, TypeScript, Python, Java, Go, Rust, C#, Ruby, PHP, Swift, Kotlin
(security scanning covers all of them; the code-quality linters cover
JavaScript/TypeScript, Python, Java, Go, Ruby, and Swift)

**Frameworks**: Express, Spring, Django, Rails, Laravel, ASP.NET, React, Vue, Angular

**Scanners**: Semgrep (SAST security analysis only), Gitleaks (secrets), Trivy (dependencies + IaC/config misconfigurations)

**Code Quality**: Always reported regardless of scan level - continuous value from every scan

**Cross-File Analysis**: Multi-file vulnerability analysis and attack chain detection

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No PR created | Verify `contents: write` and `pull-requests: write` in Settings → Actions → Workflow permissions |
| AI fix failed | Verify the AI key secret (`ANTHROPIC_API_KEY`, or `OPENAI_API_KEY` with `ai-provider: openai`) is set and valid |
| Scan timeout | Large repo? Try `scan-level: 'critical-high'` to reduce findings |
| No artifacts | Check Actions tab → workflow run → Artifacts section (30-day retention) |

## Support

- **Issues**: [GitHub Issues](https://github.com/cparnin/appsec-galaxy/issues)

---

**AppSec Galaxy is released under the MIT License.**
