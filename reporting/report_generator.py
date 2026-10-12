"""
reporting/report_generator.py

Generates pentest-style Markdown and HTML reports from a CampaignResult.
NEVER includes passwords, raw Context state, or credential values.
"""

from datetime import datetime, timezone
from core.campaign import CampaignResult
from core.technique import TechniqueResult

SEVERITY_MAP = {
    "reconnaissance":    "Informational",
    "initial-access":    "High",
    "credential-access": "Critical",
    "discovery":         "Informational",
    "lateral-movement":  "Critical",
    "persistence":       "Critical",
    "exfiltration":      "Critical",
    "impact":            "High",
}

def _severity(result: TechniqueResult) -> str:
    if not result.success:
        return "N/A"
    return SEVERITY_MAP.get(result.tactic.value, "Medium")

def _safe_evidence(evidence: dict) -> dict:
    """Strip any accidental secret-bearing keys from evidence before rendering."""
    blocked = {"password", "passwd", "secret", "token", "key", "credential"}
    return {k: v for k, v in evidence.items()
            if not any(b in k.lower() for b in blocked)}

def _md_findings_table(results: list[TechniqueResult]) -> str:
    rows = [
        "| # | Technique | ATT&CK ID | Tactic | Result | Severity | Duration |",
        "|---|-----------|-----------|--------|--------|----------|----------|",
    ]
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
        sections.append(f"### Stage {i}: {r.technique_name} ({r.attack_id})")
        sections.append(f"- **Tactic:** {r.tactic.value}")
        sections.append(f"- **Result:** {'Success' if r.success else 'Failed'}")
        sections.append(f"- **Severity:** {_severity(r)}")
        sections.append(f"- **Started:** {r.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        sections.append(f"- **Duration:** {r.duration_seconds:.2f}s")
        sections.append(f"- **Summary:** {r.summary}")
        safe = _safe_evidence(r.evidence)
        if safe:
            sections.append("- **Evidence:**")
            for k, v in safe.items():
                sections.append(f"  - `{k}`: {v}")
        if r.error:
            sections.append(f"- **Error:** `{r.error}`")
        sections.append("")
    return "\n".join(sections)

def _context_summary(cr: CampaignResult) -> str:
    ctx = cr.context
    lines = []
    if ctx.hosts:
        lines.append("**Discovered Hosts:**")
        for addr, host in ctx.hosts.items():
            lines.append(f"- `{addr}` — open ports: {host.open_ports or 'none recorded'}")
            if host.notes:
                lines.append(f"  - Notes: {host.notes}")
    # Credentials: show usernames only, never passwords
    if ctx.credentials:
        lines.append("\n**Validated Accounts (usernames only):**")
        for cred in ctx.credentials:
            lines.append(
                f"- `{cred.username}` — via {cred.source_technique}, "
                f"valid on: {cred.valid_on}"
            )
    if ctx.staged_files:
        lines.append("\n**Staged Files:**")
        for sf in ctx.staged_files:
            lines.append(f"- `{sf.path}` — {sf.description}")
    persist = ctx.extra.get("persistence_indicators", [])
    if persist:
        lines.append("\n**Persistence Indicators:**")
        for p in persist:
            lines.append(f"- {p}")
    return "\n".join(lines) if lines else "_No artifacts collected._"

def generate_markdown(cr: CampaignResult) -> str:
    total     = len(cr.stage_results)
    succeeded = sum(1 for r in cr.stage_results if r.success)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "# MyTRE Campaign Report",
        "",
        "> ⚠️ **Authorized use only.** This report documents a controlled security "
        "assessment performed on systems owned or explicitly authorized for testing.",
        "",
        "## Campaign Overview",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Campaign | {cr.campaign_name} |",
        f"| Started | {cr.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')} |",
        f"| Finished | {cr.finished_at.strftime('%Y-%m-%d %H:%M:%S UTC')} |",
        f"| Duration | {cr.duration_seconds:.2f}s |",
        f"| Stages Run | {total} |",
        f"| Stages Succeeded | {succeeded} |",
        f"| Report Generated | {generated_at} |",
        "",
        "## Executive Summary",
        "",
        (
            f"Campaign **{cr.campaign_name}** ran {total} ATT&CK-mapped technique(s), "
            f"of which {succeeded} succeeded. "
        ) + (
            "Full-chain execution confirmed from reconnaissance through exfiltration."
            if succeeded == total
            else f"{total - succeeded} stage(s) did not achieve their objective."
        ),
        "",
        "## Findings Summary",
        "",
        _md_findings_table(cr.stage_results),
        "",
        "## Artifacts Collected",
        "",
        _context_summary(cr),
        "",
        "## Stage-by-Stage Details",
        "",
        _md_stage_details(cr.stage_results),
        "---",
        "*Generated by MyTRE — ATT&CK-Mapped Adversary Emulation Framework*",
    ]
    return "\n".join(lines)

def generate_html(cr: CampaignResult) -> str:
    md = generate_markdown(cr)
    escaped = md.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MyTRE Report — {cr.campaign_name}</title>
  <style>
    *{{box-sizing:border-box;}}
    body{{font-family:system-ui,sans-serif;max-width:960px;margin:40px auto;
         padding:0 24px;line-height:1.7;color:#1a1a2e;background:#f9f9fb;}}
    h1{{color:#c0392b;border-bottom:3px solid #c0392b;padding-bottom:8px;}}
    h2{{color:#2c3e50;border-bottom:1px solid #ccc;padding-bottom:4px;margin-top:2em;}}
    h3{{color:#34495e;}}
    code{{background:#eef;padding:2px 6px;border-radius:3px;font-size:.92em;}}
    pre{{background:#1a1a2e;color:#e0e0e0;padding:16px;border-radius:6px;
         overflow-x:auto;font-size:.88em;white-space:pre-wrap;word-break:break-word;}}
    table{{border-collapse:collapse;width:100%;margin:1em 0;}}
    th,td{{border:1px solid #ccc;padding:10px 14px;text-align:left;}}
    th{{background:#2c3e50;color:#fff;}}
    tr:nth-child(even){{background:#f0f4ff;}}
    blockquote{{background:#fff8e1;border-left:4px solid #ffc107;
               padding:12px 18px;margin:0 0 1em;border-radius:0 4px 4px 0;}}
    .footer{{margin-top:48px;color:#888;font-size:.83em;text-align:center;}}
    @media(prefers-color-scheme:dark){{
      body{{color:#d0d0d0;background:#12121f;}}
      h1{{color:#e74c3c;}} h2{{color:#89b4fa;}} h3{{color:#cdd6f4;}}
      code{{background:#2a2a3e;}} table{{color:#d0d0d0;}}
      th{{background:#1e3a5f;}} tr:nth-child(even){{background:#1e1e2e;}}
      blockquote{{background:#2a2a1e;border-color:#d4a000;}}
    }}
  </style>
</head>
<body>
<pre>{escaped}</pre>
<div class="footer">Generated by MyTRE — ATT&CK-Mapped Adversary Emulation Framework</div>
</body>
</html>"""

def save_report(cr: CampaignResult, output_dir: str = "reports") -> dict[str, str]:
    import os
    os.makedirs(output_dir, exist_ok=True)
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    slug = cr.campaign_name.lower().replace(" ", "_")
    md_path   = os.path.join(output_dir, f"{slug}_{ts}.md")
    html_path = os.path.join(output_dir, f"{slug}_{ts}.html")
    with open(md_path,   "w", encoding="utf-8") as f: f.write(generate_markdown(cr))
    with open(html_path, "w", encoding="utf-8") as f: f.write(generate_html(cr))
    return {"markdown": md_path, "html": html_path}
