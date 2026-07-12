# AppSec Galaxy MCP server

The FastMCP server gives ChatGPT desktop, Codex, and other MCP clients access
to AppSec Galaxy scans, findings, reports, SBOMs, and remediation workflows.
It exposes 16 tools and four artifact resources over stdio.

## Prerequisites

From the repository root:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e ".[web,dev]"
```

Install Gitleaks, Trivy, and Syft separately for secrets, dependency, and SBOM
features. Semgrep is installed with the Python project.

Set credentials in the process that launches the MCP server:

```bash
export APPSEC_GALAXY_PATH="$PWD"
export OPENAI_API_KEY="your-openai-api-key-here"  # optional until AI is used
# Or use Claude models instead:
# export AI_PROVIDER="anthropic"
# export ANTHROPIC_API_KEY="your-anthropic-api-key-here"
export GITHUB_TOKEN="your-github-token-here"      # required only for PR creation
```

Do not put credentials in MCP client configuration. Importing and initializing
the server does not construct an OpenAI client or require a key.

## Codex configuration

The repository includes this local configuration:

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
| `auto_remediate` | Generate constrained fixes and draft PRs |
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

`{repo}` may be a repository name or a validated path. Resources return the
current artifact under `outputs/<repository>/`.

## Optional Claude Desktop compatibility

Claude Desktop can use the same stdio JSON configuration shown above. This is
an MCP compatibility option only; AppSec Galaxy's AI provider remains OpenAI.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Server cannot find the installation | Set `APPSEC_GALAXY_PATH` or launch from the checkout |
| No tools appear | Confirm absolute paths, JSON/TOML syntax, and restart the client |
| Repository not found | Pass an absolute path or set `REPO_SEARCH_PATHS` |
| AI feature unavailable | Export a valid `OPENAI_API_KEY` (or `ANTHROPIC_API_KEY` with `AI_PROVIDER=anthropic`) in the server process |
| PR creation unavailable | Export `GITHUB_TOKEN` with repository permissions |
| Scanner missing | Install the external binary and confirm it is on `PATH` |

Smoke-test the server module without a live model call:

```bash
env -u OPENAI_API_KEY .venv/bin/python -c '
import importlib.util
p = "mcp/appsec_galaxy_mcp_server.py"
s = importlib.util.spec_from_file_location("appsec_galaxy_mcp_server", p)
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)
print(m.SERVER_NAME)
'
```

Expected output: `appsec-galaxy`.
