# AppSec Galaxy Setup

AI-powered security scanner for any programming language. Detects vulnerabilities and can create fix PRs.

## Quick Setup (3 steps)

### 1. Add Workflow
```bash
cp security-scan.yml .github/workflows/
```

### 2. Configure Credentials

Go to **Settings → Secrets and variables → Actions** and add one secret:

- `OPENAI_API_KEY` - get one at https://platform.openai.com/api-keys
  (or use Claude: set `ai-provider: 'anthropic'` in the workflow and add an
  `ANTHROPIC_API_KEY` secret from https://console.anthropic.com/settings/keys)

That's it. The workflow template is already wired to use it.

### 3. Commit and Push
```bash
git add .github/workflows/security-scan.yml
git commit -m "Add AppSec Galaxy security scanning"
git push
```

## What You Get

- ✅ **Automated scans** on every PR
- ✅ **AI-generated fixes** for code vulnerabilities
- ✅ **Separate PRs** for code fixes vs dependency updates
- ✅ **HTML reports** with business impact analysis
- ✅ **Auto SBOM** (CycloneDX & SPDX) for compliance
- ✅ **Artifacts** - Reports and SBOM files (90-day retention)

## Configuration Options

Default settings (customize in `security-scan.yml`):
```yaml
with:
  openai-api-key: ${{ secrets.OPENAI_API_KEY }}
  ai-model: ''                   # Optional model override
  scan-level: 'critical-high'    # Or 'all' (affects security findings only)
  auto-fix: 'true'               # Generate fix PRs
  auto-fix-mode: '3'             # 1=SAST, 2=deps, 3=both, 4=none
  fail-on-critical: 'false'      # Don't break CI by default

# Note: Code quality findings are ALWAYS shown regardless of scan-level
```

## Supported Languages & Frameworks

**Languages**: JavaScript, Python, Java, Go, Rust, C#, Ruby, PHP, Swift, Kotlin, TypeScript

**Frameworks**: Express, Spring, Django, Rails, Laravel, ASP.NET, React, Vue, Angular

**Scanners**: Semgrep (SAST security analysis only), Gitleaks (secrets), Trivy (dependencies + IaC/config misconfigurations)

**Code Quality**: Always reported regardless of scan level - continuous value from every scan

**Cross-File Analysis**: Multi-file vulnerability analysis and attack chain detection

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No PR created | Verify `contents: write` and `pull-requests: write` in Settings → Actions → Workflow permissions |
| AI fix failed | Verify the AI key secret (`OPENAI_API_KEY` or `ANTHROPIC_API_KEY`) is set and valid |
| Scan timeout | Large repo? Try `scan-level: 'critical-high'` to reduce findings |
| No artifacts | Check Actions tab → workflow run → Artifacts section (90-day retention) |

## Support

- **Issues**: [GitHub Issues](https://github.com/cparnin/appsec-galaxy/issues)

---

**AppSec Galaxy is released under the MIT License.**
