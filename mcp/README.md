# AppSec Galaxy MCP server

The FastMCP server gives ChatGPT desktop, Codex, and other MCP clients access
to AppSec Galaxy scans, findings, reports, SBOMs, and remediation workflows.
It exposes 16 tools and four artifact resources over stdio.

## Prerequisites

From the repository root:

```bash
python3 -m venv .venv    # any Python 3.11-3.13
.venv/bin/python -m pip install -e ".[web,dev]"
```

Install Gitleaks, Trivy, and Syft for secrets, dependency, and SBOM features
(macOS: `brew install gitleaks trivy syft`; Linux: see each project's releases
page). Semgrep is installed with the Python project.

Set credentials in the process that launches the MCP server:

```bash
export APPSEC_GALAXY_PATH="$PWD"
export ANTHROPIC_API_KEY="your-anthropic-api-key-here"  # optional until AI is used
# Or use OpenAI models instead:
# export AI_PROVIDER="openai"
# export OPENAI_API_KEY="your-openai-api-key-here"
export GITHUB_TOKEN="your-github-token-here"            # required only for PR creation
```

Do not put credentials in MCP client configuration. Importing and initializing
the server does not construct a provider client or require a key.

The server will only scan repositories under `~/repos` and `~/projects`. To
allow other locations, set `APPSEC_MCP_ALLOWED_ROOTS` to a colon-separated
list; it replaces the defaults rather than adding to them, and anything
outside it is refused (the home directory and the server's working directory
are deliberately not allowed roots).

```bash
export APPSEC_MCP_ALLOWED_ROOTS="$HOME/code:$HOME/work"
```

## Codex configuration

Create `.codex/config.toml` (git-ignored) with:

```toml
[mcp_servers.appsec-galaxy]
command = ".venv/bin/python"
args = ["mcp/appsec_galaxy_mcp_server.py"]
```

Launch Codex from the repository root so the relative paths resolve.

## ChatGPT desktop configuration

Add a stdio MCP server using the checkout's absolute paths:

```json
{
  "mcpServers": {
    "appsec-galaxy": {
      "command": "/path/to/appsec-galaxy/.venv/bin/python",
      "args": [
        "/path/to/appsec-galaxy/mcp/appsec_galaxy_mcp_server.py"
      ]
    }
  }
}
```

Restart the client after updating its MCP configuration.

## Tools

| Tool | Purpose |
| --- | --- |
| `scan_repository` | Start a full scan in the background |
| `auto_remediate` | Generate constrained fixes and open PRs |
| `get_report` | Read the current findings summary |
| `generate_sbom` | Generate CycloneDX/SPDX SBOMs |
| `cross_file_analysis` | Analyze entry points, sinks, and attack paths |
| `assess_business_impact` | Summarize risk and impact |
| `view_report_html` | Open/read the HTML report location |
| `get_scan_findings` | Return normalized findings with pagination |
| `get_semgrep_findings` | Return SAST findings |
| `get_trivy_findings` | Return dependency findings |
| `get_gitleaks_findings` | Return secret findings |
| `get_code_quality_findings` | Return language-linter findings |
| `get_sbom_data` | Read generated SBOM data |
| `health_check` | Check installation, tools, and configuration |
| `analyze_dependency_health` | Trace package usage and maintenance health |
| `get_dependency_usage` | Explain one package's code paths |

Every repository argument is validated before discovery or subprocess use.
Scans run asynchronously; poll `get_scan_findings` for completion.

## Resources

| URI template | Artifact |
| --- | --- |
| `appsec-galaxy://{repo}/report.html` | Full HTML report |
| `appsec-galaxy://{repo}/report.sarif` | SARIF 2.1.0 log |
| `appsec-galaxy://{repo}/sbom.cyclonedx.json` | CycloneDX SBOM |
| `appsec-galaxy://{repo}/sbom.spdx.json` | SPDX SBOM |

`{repo}` is a repository NAME (a single path segment), not a path: the
resource template matches one segment. Resources return the current
artifact under `outputs/<repository>/`. Use the tools for path targets.

## Optional Claude Desktop compatibility

Claude Desktop can use the same stdio JSON configuration shown above.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Server cannot find the installation | Set `APPSEC_GALAXY_PATH` or launch from the checkout |
| No tools appear | Confirm absolute paths, JSON/TOML syntax, and restart the client |
| Repository not found, or "outside the allowed scan roots" | The server only scans under `~/repos` and `~/projects` by default. Set `APPSEC_MCP_ALLOWED_ROOTS` (colon-separated) to allow other locations; it replaces the defaults entirely |
| AI feature unavailable | Export a valid `ANTHROPIC_API_KEY` (or `OPENAI_API_KEY` with `AI_PROVIDER=openai`) in the server process |
| PR creation unavailable | Export `GITHUB_TOKEN` with repository permissions |
| Scanner missing | Install the external binary and confirm it is on `PATH` |

Smoke-test the server module without a live model call:

```bash
env -u ANTHROPIC_API_KEY -u OPENAI_API_KEY .venv/bin/python -c '
import importlib.util
p = "mcp/appsec_galaxy_mcp_server.py"
s = importlib.util.spec_from_file_location("appsec_galaxy_mcp_server", p)
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)
print(m.SERVER_NAME)
'
```

Expected output: `appsec-galaxy`.
