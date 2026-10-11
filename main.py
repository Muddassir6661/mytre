#!/usr/bin/env python3
"""
main.py — MyTRE CLI entry point

Usage:
    python main.py run campaigns/homelab_assessment.yaml
    python main.py run campaigns/homelab_assessment.yaml --target 192.168.0.115
    python main.py run campaigns/homelab_assessment.yaml --report-dir reports/
"""

import argparse
import sys
import os

BANNER = r"""
  __  __   _   _  ____   ____  _____ 
 |  \/  | | | | ||_  _| |  _ \| ____|
 | |\/| | | |_| |  | |  | |_) |  _|  
 | |  | | |_   _|  | |  |  _ <| |___ 
 |_|  |_|   |_|   |_|  |_| \_\_____|

 MyTRE — ATT&CK-Mapped Adversary Emulation Framework
 ⚠️  Authorized use only. Test only systems you own or have
    explicit written permission to assess.
"""


def cmd_run(args: argparse.Namespace) -> int:
    from core.campaign import Campaign
    from core.context import Context
    from reporting.report_generator import save_report

    print(BANNER)
    print(f"[*] Loading campaign: {args.campaign_file}")

    try:
        campaign = Campaign.from_yaml(args.campaign_file)
    except Exception as exc:
        print(f"[!] Failed to load campaign: {exc}", file=sys.stderr)
        return 1

    context = Context(primary_target=args.target)
    print(f"[*] Campaign: {campaign.name}")
    print(f"[*] Stages:   {len(campaign.stages)}")
    if args.target:
        print(f"[*] Target override: {args.target}")
    print(f"[*] Starting run...\n")

    result = campaign.run(context)

    print(f"\n{'='*60}")
    print(f"  Campaign complete: {result.campaign_name}")
    print(f"  Duration:          {result.duration_seconds:.2f}s")
    print(f"{'='*60}")
    for i, r in enumerate(result.stage_results, 1):
        icon = "✅" if r.success else "❌"
        print(f"  {icon}  Stage {i}: {r.technique_name} ({r.attack_id}) — {r.summary}")
    print(f"{'='*60}\n")

    paths = save_report(result, output_dir=args.report_dir)
    print(f"[*] Report saved:")
    print(f"    Markdown → {paths['markdown']}")
    print(f"    HTML     → {paths['html']}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="MyTRE — ATT&CK-Mapped Adversary Emulation Framework"
    )
    sub = parser.add_subparsers(dest="command")

    run_p = sub.add_parser("run", help="Run a campaign from a YAML file")
    run_p.add_argument("campaign_file", help="Path to campaign YAML")
    run_p.add_argument("--target", default=None, help="Override primary target IP")
    run_p.add_argument("--report-dir", default="reports", help="Output directory for reports")

    args = parser.parse_args()

    if args.command == "run":
        sys.exit(cmd_run(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
