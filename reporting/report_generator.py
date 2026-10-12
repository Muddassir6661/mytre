"""
reporting/report_generator.py

Consumes a completed CampaignResult and renders a structured pentest-
style findings report in Markdown and HTML. The report generator
never re-runs anything — it only reads what the campaign already
produced (TechniqueResults + final Context state).
"""

from datetime import datetime, timezone
from core.campaign import CampaignResult
from core.technique import TechniqueResult


SEVERITY_MAP = {
    "reconnaissance": "Not assessed",
    "initial-access": "Not assessed",
    "credential-access": "Not assessed",
    "lateral-movement": "Not assessed",
    "exfiltration": "Not assessed",
    "impact": "Not assessed",
}


def _severity(result: TechniqueResult) -> str:
    if not result.success:
        return "N/A"
    return SEVERITY_MAP.get(result.tactic.value, "Medium")


def _md_findings_table(results: list[TechniqueResult]) -> str:
    rows = []
    rows.append("| # | Technique | ATT&CK ID | Tactic | Result | Severity | Duration |")
    rows.append("|---|-----------|-----------|--------|--------|----------|----------|")
    for i, r in enumerate(results, 1):
        status = "✅ Success" if r.success else "❌ Failed"
        rows.append(
            f"| {i} | {r.technique_name} | {r.attack_id} "
            f"| {r.tactic.value} | {status} | {_severity(r)} "
            f"| {r.duration_seconds:.2f}s |"
        )
    return "\n".join(rows)


def _md_stage_details(results: list[TechniqueResult]) -> str:
    sections = []
    for i, r in enumerate(results, 1):
        status = "Success" if r.success else "Failed"
        sections.append(f"### Stage {i}: {r.technique_name} ({r.attack_id})")
        sections.append(f"- **Tactic:** {r.tactic.value}")
        sections.append(f"- **Result:** {status}")
        sections.append(f"- **Severity:** {_severity(r)}")
        sections.append(f"- **Started:** {r.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        sections.append(f"- **Duration:** {r.duration_seconds:.2f}s")
        sections.append(f"- **Summary:** {r.summary}")
        if r.evidence:
            sections.append("- **Evidence:**")
            for k, v in r.evidence.items():
                sections.append(f"  - `{k}`: {v}")
        if r.error:
            sections.append(f"- **Error:** `{r.error}`")
        sections.append("")
    return "\n".join(sections)


def _context_summary(campaign_result: CampaignResult) -> str:
    ctx = campaign_result.context
    lines = []

    if ctx.hosts:
        lines.append("**Discovered Hosts:**")
        for addr, host in ctx.hosts.items():
            lines.append(f"- `{addr}` — open ports: {host.open_ports or 'none recorded'}")
            if host.notes:
                lines.append(f"  - Notes: {host.notes}")

    if ctx.credentials:
        lines.append("\n**Harvested Credentials:**")
        for cred in ctx.credentials:
            lines.append(
                f"- `{cred.username}` / `{'*' * len(cred.password or '')}` "
                f"(via {cred.source_technique}, valid on: {cred.valid_on})"
            )

    if ctx.staged_files:
        lines.append("\n**Staged Files:**")
        for sf in ctx.staged_files:
            lines.append(f"- `{sf.path}` — {sf.description}")

    return "\n".join(lines) if lines else "_No artifacts collected._"


def generate_markdown(campaign_result: CampaignResult) -> str:
    r = campaign_result
    total = len(r.stage_results)
    succeeded = sum(1 for s in r.stage_results if s.success)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        f"# MyTRE Campaign Report",
        f"",
        f"> ⚠️ **Authorized use only.** This report documents a controlled security assessment "
        f"performed on systems owned or explicitly authorized for testing.",
        f"",
        f"## Campaign Overview",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Campaign | {r.campaign_name} |",
        f"| Started | {r.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')} |",
        f"| Finished | {r.finished_at.strftime('%Y-%m-%d %H:%M:%S UTC')} |",
        f"| Duration | {r.duration_seconds:.2f}s |",
        f"| Stages Run | {total} |",
        f"| Stages Succeeded | {succeeded} |",
        f"| Report Generated | {generated_at} |",
        f"",
        f"## Executive Summary",
        f"",
        f"Campaign **{r.campaign_name}** ran {total} ATT&CK-mapped technique(s), "
        f"of which {succeeded} succeeded. "
        + (
            "All configured stages completed successfully."
            if total > 0 and succeeded == total
            else f"{total - succeeded} of {total} stage(s) did not achieve their objective."
        ),
        f"",
        f"## Findings Summary",
        f"",
        _md_findings_table(r.stage_results),
        f"",
        f"## Artifacts Collected",
        f"",
        _context_summary(campaign_result),
        f"",
        f"## Stage-by-Stage Details",
        f"",
        _md_stage_details(r.stage_results),
        f"---",
        f"*Generated by MyTRE — ATT&CK-Mapped Adversary Emulation Framework*",
    ]
    return "\n".join(lines)


def generate_html(campaign_result: CampaignResult) -> str:
    md_body = generate_markdown(campaign_result)
    # Minimal HTML wrapper — clean enough for a recruiter to open and read
    escaped = md_body.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>MyTRE Report — {campaign_result.campaign_name}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; line-height: 1.6; color: #222; }}
    h1 {{ color: #c0392b; }} h2 {{ color: #2c3e50; border-bottom: 1px solid #ddd; padding-bottom: 4px; }}
    h3 {{ color: #34495e; }} code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }}
    pre {{ background: #f4f4f4; padding: 12px; border-radius: 4px; overflow-x: auto; }}
    table {{ border-collapse: collapse; width: 100%; }} th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
    th {{ background: #2c3e50; color: white; }} tr:nth-child(even) {{ background: #f9f9f9; }}
    blockquote {{ background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px 16px; margin: 0; }}
    footer {{ margin-top: 40px; color: #888; font-size: 0.85em; }}
  </style>
</head>
<body>
<pre>{escaped}</pre>
<footer>Generated by MyTRE — ATT&CK-Mapped Adversary Emulation Framework</footer>
</body>
</html>"""


def save_report(campaign_result: CampaignResult, output_dir: str = "reports") -> dict[str, str]:
    """Save both MD and HTML reports; return paths to both."""
    import os
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    slug = campaign_result.campaign_name.lower().replace(" ", "_")

    md_path = os.path.join(output_dir, f"{slug}_{ts}.md")
    html_path = os.path.join(output_dir, f"{slug}_{ts}.html")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write(generate_markdown(campaign_result))
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(generate_html(campaign_result))

    return {"markdown": md_path, "html": html_path}
