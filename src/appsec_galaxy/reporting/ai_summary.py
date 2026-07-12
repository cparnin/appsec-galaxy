"""
AI-powered executive summary generator for AppSec Galaxy HTML reports.

When APPSEC_AI_SCAN=true, replaces the static templated summary with a real
LLM-generated executive summary that synthesizes findings into actionable
business context: risk narrative, prioritized recommendations, estimated
remediation effort, and compliance implications.

Falls back to static summary when AI is disabled or unavailable.
"""

import html
import json
import os
import re
import time
from typing import Any

from appsec_galaxy.logging_config import get_logger

logger = get_logger(__name__)

# Cost cap: executive summary should be cheap (one call, small prompt)
MAX_SUMMARY_TOKENS = 2048
SUMMARY_TIMEOUT_SECONDS = 30


def _markdown_to_html(text: str) -> str:
    """Convert lightweight markdown to safe HTML for the report template.

    Handles: **bold**, *italic*, # headers, - bullet lists, numbered lists,
    and newlines. HTML-escapes everything first to prevent injection.
    """
    text = html.escape(text)

    # Full-line bold ("**Recommended Actions:**") marks a topic heading.
    # The report wraps each topic and its content in a bordered block
    # (see _wrap_topic_sections). Trailing colon dropped for display.
    text = re.sub(r'^\*\*([^*\n]+?):?\*\*:?\s*$', r'<h4 class="summary-topic">\1</h4>',
                  text, flags=re.MULTILINE)

    # Headers: ### h3, ## h2, # h1 (must be at line start)
    text = re.sub(r'^### +(.+)$', r'<h4 class="summary-topic">\1</h4>', text, flags=re.MULTILINE)
    text = re.sub(r'^## +(.+)$', r'<h3 class="summary-topic">\1</h3>', text, flags=re.MULTILINE)
    text = re.sub(r'^# +(.+)$', r'<h3 class="summary-topic">\1</h3>', text, flags=re.MULTILINE)

    # Bold: **text**
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    # Italic: *text*
    text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)

    # Bullet lists: lines starting with - or *
    text = re.sub(r'^[*\-] +(.+)$', r'<li>\1</li>', text, flags=re.MULTILINE)
    # Numbered lists: lines starting with 1. 2. etc.
    text = re.sub(r'^\d+\. +(.+)$', r'<li>\1</li>', text, flags=re.MULTILINE)

    # Wrap consecutive <li> in <ul>. Strip intra-list whitespace so the
    # later `\n -> <br>` rule cannot inject blank lines between bullets
    # (that produced the giant gaps between list items in old reports).
    def _wrap_ul(match):
        inner = re.sub(r'\s*\n\s*', '', match.group(0))
        return f'<ul style="margin:0.3em 0;padding-left:1.5em;">{inner}</ul>'
    text = re.sub(r'(?:<li>.*?</li>\s*)+', _wrap_ul, text)

    # Paragraphs: double newlines become paragraph breaks
    text = re.sub(r'\n{2,}', '</p><p>', text)
    # Single newlines become <br>
    text = text.replace('\n', '<br>\n')

    # Wrap in paragraph tags
    text = f'<p>{text}</p>'
    # <ul>, <h3>, <h4> are block-level and must not live inside a <p>
    # (browsers auto-close the <p> before them, producing inconsistent
    # rendering). Unwrap so the HTML validates and renders predictably.
    text = re.sub(r'<p>\s*(<(?:ul|h[1-6])[^>]*>)', r'\1', text)
    text = re.sub(r'(</(?:ul|h[1-6])>)\s*</p>', r'\1', text)
    # Clean up empty paragraphs
    text = text.replace('<p></p>', '')

    return _wrap_topic_sections(text)


def _wrap_topic_sections(text: str) -> str:
    """Wrap each topic heading and its content in a bordered block.

    Splits at summary-topic headings so the report renders one visually
    separated card per topic (Security Issues, Recommended Actions, ...).
    Content before the first heading becomes an unboxed intro. No-op when
    the summary has no topic headings."""
    parts = re.split(r'(?=<h[34] class="summary-topic")', text)
    if len(parts) < 2:
        return text
    out = []
    if parts[0].strip():
        out.append(f'<div class="summary-intro">{parts[0]}</div>')
    for part in parts[1:]:
        out.append(f'<div class="summary-topic-block">{part}</div>')
    return ''.join(out)


def _get_ai_client_and_model():
    """Get the shared AI client and summary model from ai_scanner.
    Returns (client, model_id) or (None, None)."""
    try:
        from appsec_galaxy.scanners.ai_scanner import _get_ai_client, _get_model_id
        client = _get_ai_client()
        # Use the standard depth for balanced summary quality and cost.
        model_id = _get_model_id('standard')
        return client, model_id
    except Exception as e:
        logger.warning(f"AI summary: could not initialize AI client: {e}")
        return None, None


def _call_ai(client, model_id: str, system_prompt: str, user_message: str) -> str | None:
    """Make an AI call for the summary."""
    try:
        from appsec_galaxy.scanners.ai_scanner import _call_ai as _scanner_call_ai
        return _scanner_call_ai(client, model_id, system_prompt, user_message, MAX_SUMMARY_TOKENS)
    except Exception as e:
        logger.error(f"AI summary call failed: {e}")
        return None


def _build_findings_digest(findings: list[dict[str, Any]], cross_file_data: dict | None = None) -> str:
    """
    Build a compact digest of findings for the LLM prompt.
    Keeps it small to control cost, but includes enough signal for a good summary.
    """
    # Separate by category
    security = [f for f in findings if f.get('extra', {}).get('metadata', {}).get('category') != 'code_quality']
    code_quality = [f for f in findings if f.get('extra', {}).get('metadata', {}).get('category') == 'code_quality']

    # Count by tool and severity
    by_tool: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for f in security:
        tool = f.get('tool', 'unknown')
        sev = f.get('severity', 'unknown').lower()
        by_tool[tool] = by_tool.get(tool, 0) + 1
        by_severity[sev] = by_severity.get(sev, 0) + 1

    lines = [
        f"Total security findings: {len(security)}",
        f"Total code quality findings: {len(code_quality)}",
        f"By tool: {json.dumps(by_tool)}",
        f"By severity: {json.dumps(by_severity)}",
    ]

    # Top 15 most critical findings (enough context without blowing up tokens)
    severity_rank = {'critical': 0, 'high': 1, 'error': 1, 'medium': 2, 'low': 3}
    ranked = sorted(security, key=lambda f: severity_rank.get(f.get('severity', '').lower(), 4))

    lines.append("\nTop findings:")
    for i, f in enumerate(ranked[:15]):
        msg = f.get('extra', {}).get('message', f.get('message', 'No description'))
        if len(msg) > 200:
            msg = msg[:200] + '...'
        check_id = f.get('check_id', '')
        sev = f.get('severity', 'unknown')
        tool = f.get('tool', 'unknown')
        path = f.get('path', '')
        line_num = f.get('start', {}).get('line', '')
        lines.append(f"  {i+1}. [{sev}] {tool}: {msg}")
        if check_id:
            lines.append(f"     Rule: {check_id}")
        if path:
            lines.append(f"     File: {path}:{line_num}")

    # Cross-file attack chains if available
    if cross_file_data:
        chains = cross_file_data.get('attack_chains', [])
        if chains:
            lines.append(f"\nCross-file attack chains ({len(chains)}):")
            for chain in chains[:5]:
                lines.append(f"  - {chain.get('type', '?')}: {chain.get('entry_point', '?')} -> {chain.get('sink', '?')} (severity: {chain.get('severity', '?')})")
                if chain.get('ai_validated') is not None:
                    lines.append(f"    AI validated: {chain.get('ai_validated')}, exploitability: {chain.get('ai_exploitability', 'unknown')}")

        # Compound risks
        compounds = cross_file_data.get('compound_risk_groups', [])
        if compounds:
            lines.append(f"\nCompound risks ({len(compounds)}):")
            for c in compounds[:3]:
                lines.append(f"  - {c.get('risk', '?')} (severity: {c.get('severity', '?')})")

    # Gitleaks summary (don't leak actual secrets into prompt)
    secrets = [f for f in security if f.get('tool') == 'gitleaks']
    if secrets:
        secret_types: dict[str, int] = {}
        for s in secrets:
            desc = s.get('extra', {}).get('description', s.get('description', 'unknown'))
            secret_types[desc] = secret_types.get(desc, 0) + 1
        lines.append(f"\nSecrets detected: {json.dumps(secret_types)}")

    # Trivy dep summary
    deps = [f for f in security if f.get('tool') == 'trivy']
    if deps:
        dep_sevs: dict[str, int] = {}
        for d in deps:
            sev = d.get('severity', 'unknown').lower()
            dep_sevs[sev] = dep_sevs.get(sev, 0) + 1
        lines.append(f"\nVulnerable dependencies: {len(deps)} total, severity breakdown: {json.dumps(dep_sevs)}")

    return '\n'.join(lines)


def generate_ai_executive_summary(
    findings: list[dict[str, Any]],
    repo_path: str,
    cross_file_data: dict | None = None,
    static_summary: str = "",
) -> str:
    """
    Generate an AI-powered executive summary for the HTML report.

    Calls the configured AI provider to synthesize findings into a business-focused
    narrative. Falls back to static_summary if AI is disabled or fails.

    Args:
        findings: All scan findings
        repo_path: Path to scanned repository
        cross_file_data: Cross-file analysis context (attack chains, compounds)
        static_summary: Fallback static summary

    Returns:
        Executive summary string (may contain markdown-like formatting)
    """
    # Gate: only run when AI scanning is enabled
    ai_enabled = os.getenv('APPSEC_AI_SCAN', 'false').lower() == 'true'
    if not ai_enabled:
        logger.debug("AI summary: APPSEC_AI_SCAN is not enabled, using static summary")
        return static_summary

    # Gate: privacy tier check
    tier = int(os.getenv('APPSEC_AI_SCAN_TIER', '3'))
    if tier < 2:
        logger.debug("AI summary: tier 1 (no AI), using static summary")
        return static_summary

    # Gate: must have findings to summarize
    if not findings:
        return static_summary

    client, model_id = _get_ai_client_and_model()
    if not client:
        logger.warning("AI summary: AI client unavailable, falling back to static summary")
        return static_summary

    # Build the digest
    digest = _build_findings_digest(findings, cross_file_data)
    repo_name = os.path.basename(repo_path)

    system_prompt = """You are a senior security architect writing an executive summary for a security scan report. Your audience is engineering leadership and security teams.

Rules:
- Be direct and specific. No filler, no generic advice.
- Lead with the most critical risk, not a count of findings.
- Mention specific vulnerability types, not "various security issues."
- Include estimated remediation effort (hours/days, not vague timeframes).
- If attack chains exist, highlight the most dangerous one by name.
- If secrets are exposed, state the urgency clearly.
- End with 3-5 prioritized, specific action items.
- Use plain text with ** for bold on key terms. No markdown headers.
- Never use em dashes or en dashes. Use commas, periods, or colons instead.
- Keep it under 300 words. Dense, not verbose.
- Do not fabricate findings. Only reference what appears in the data."""

    user_message = f"""<scan_data>
<repository>{repo_name}</repository>
<findings>
{digest}
</findings>
</scan_data>

Write an executive summary for this security scan. Focus on business risk, not just vulnerability counts."""

    start = time.time()
    try:
        result = _call_ai(client, model_id, system_prompt, user_message)
        elapsed = time.time() - start
        logger.info(f"AI summary: generated in {elapsed:.1f}s")

        if result and len(result.strip()) > 50:
            return result.strip()
        else:
            logger.warning("AI summary: response too short or empty, falling back to static")
            return static_summary
    except Exception as e:
        logger.error(f"AI summary generation failed: {e}")
        return static_summary
