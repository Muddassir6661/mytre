#!/usr/bin/env python3
"""
main.py — MyTRE CLI entry point

Usage:
    python main.py run campaigns/homelab_integrated.yaml
    python main.py run campaigns/homelab_integrated.yaml --target 192.168.0.115
"""

import argparse
import ipaddress
import os
import sys
import time

from core import campaign
from core.campaign import Campaign

def _banner() -> str:
    r = "\033[91m" if _COLOR else ""   # bright red
    c = "\033[96m" if _COLOR else ""   # cyan
    y = "\033[93m" if _COLOR else ""   # yellow
    b = "\033[1m"  if _COLOR else ""   # bold
    x = "\033[0m"  if _COLOR else ""   # reset
    return f"""{r}
  __  __   _   _  ____   ____  _____ 
 |  \\/  | | | | ||_  _| |  _ \\| ____|
 | |\\/| | | |_| |  | |  | |_) |  _|  
 | |  | | |_   _|  | |  |  _ <| |___ 
 |_|  |_|   |_|   |_|  |_| \\_\\_____|{x}

 {b}{c}MyTRE{x} {b}— ATT&CK-Mapped Adversary Emulation Framework{x}
 
{y}⚠️  Authorized use only. Test only systems you own or have explicit written permission to assess.{x}
"""

# ── ANSI colour helpers (fallback to plain text if unsupported) ──────────────

def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

_COLOR = _supports_color()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text

def green(t):  return _c("92", t)
def red(t):    return _c("91", t)
def yellow(t): return _c("93", t)
def cyan(t):   return _c("96", t)
def bold(t):   return _c("1",  t)
def dim(t):    return _c("2",  t)


# ── Progress callback ─────────────────────────────────────────────────────────

_stage_start_time: float = 0.0

def print_progress(event: dict) -> None:
    etype = event["event"]

    if etype == "stage_start":
        global _stage_start_time
        _stage_start_time = time.time()
        label = f"Stage {event['index']}/{event['total']}"
        print(
            f"\n{bold(label)} — {cyan(event['technique_name'])} "
            f"{dim('(' + event['attack_id'] + ')')}"
        )
        print(f"  {yellow('RUNNING')}  {event['tactic']}")

    elif etype == "stage_end":
        elapsed = time.time() - _stage_start_time
        status = green("SUCCESS") if event["success"] else red("FAILED ")
        print(f"  {status}  {event['summary']}  {dim(f'({elapsed:.2f}s)')}")

    elif etype == "campaign_aborted":
        print(f"\n  {red('ABORTED')}  Stage {event['index']} failed with "
              f"continue_on_failure=false: {event['reason']}")


# ── Input validation ──────────────────────────────────────────────────────────

def _validate_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {value!r}")


def _validate_port(value: str) -> int:
    try:
        p = int(value)
        if not 1 <= p <= 65535:
            raise ValueError
        return p
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid port: {value!r}")


def _prompt_ip(prompt_text: str, default: str | None = None) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        raw = input(f"{prompt_text}{suffix}: ").strip()
        if not raw and default:
            return default
        try:
            ipaddress.ip_address(raw)
            return raw
        except ValueError:
            print(f"  {red('Invalid IP address, try again.')}")


def _prompt_port(prompt_text: str, default: int) -> int:
    while True:
        raw = input(f"{prompt_text} [{default}]: ").strip()
        if not raw:
            return default
        try:
            p = int(raw)
            if 1 <= p <= 65535:
                return p
        except ValueError:
            pass
        print(f"  {red('Invalid port (1–65535), try again.')}")


# ── Preflight checks ──────────────────────────────────────────────────────────

def _preflight(campaign_file: str) -> bool:
    ok = True
    if not os.path.isfile(campaign_file):
        print(red(f"  [!] Campaign file not found: {campaign_file}"))
        ok = False
    if not os.path.isdir("wordlists"):
        print(yellow("  [!] wordlists/ directory not found — brute-force stages may fail"))
    if not os.path.isdir("techniques"):
        print(red("  [!] techniques/ directory not found — cannot load any modules"))
        ok = False
    return ok


def _select_stages(campaign: "Campaign") -> list[int]:
    """
    Interactive stage selector. Returns list of 1-based stage indices to run.
    Default (empty input) = all stages.
    """
    print(f"\n  {bold('Available stages:')}")
    for i, s in enumerate(campaign.stages, 1):
        print(f"    {dim(str(i)+'.')} {cyan(s.class_name)} "
              f"{dim('('+s.module_path.split('.')[-1]+')')}")
    print()
    raw = input(
        bold("Stages to run (e.g. 1,3,5-8 or press Enter for all): ")
    ).strip()
    if not raw:
        return list(range(1, len(campaign.stages) + 1))

    selected = set()
    for part in raw.split(","):
        part = part.strip()
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                selected.update(range(int(a), int(b) + 1))
            except ValueError:
                print(red(f"  Skipping invalid range: {part}"))
        else:
            try:
                selected.add(int(part))
            except ValueError:
                print(red(f"  Skipping invalid value: {part}"))

    valid = sorted(i for i in selected if 1 <= i <= len(campaign.stages))
    if not valid:
        print(yellow("  No valid stages selected — running all."))
        return list(range(1, len(campaign.stages) + 1))
    return valid


# ── Run command ───────────────────────────────────────────────────────────────

def cmd_run(args: argparse.Namespace) -> int:
    from core.campaign import Campaign, CampaignLoadError
    from core.context import Context
    from reporting.report_generator import save_report

    print(_banner())

    if not _preflight(args.campaign_file):
        return 1

    # Gather target / ports interactively if not supplied
    target_ip = args.target or _prompt_ip("Target IP")
    ssh_port   = args.ssh_port   or _prompt_port("SSH port",      22)
    recv_port  = args.recv_port  or _prompt_port("Receiver port", 8081)

    variables = {
        "TARGET_IP":     target_ip,
        "SSH_PORT":      ssh_port,
        "RECEIVER_PORT": recv_port,
    }

    print(f"\n  {bold('Campaign:')}  {args.campaign_file}")
    print(f"  {bold('Target:')}    {target_ip}")
    print(f"  {bold('SSH port:')} {ssh_port}   "
          f"{bold('Receiver port:')} {recv_port}")

    try:
        campaign = Campaign.from_yaml(args.campaign_file, variables=variables)
    except CampaignLoadError as exc:
        print(red(f"\n[!] Failed to load campaign: {exc}"))
        return 1

    print(f"  {bold('Stages:')}    {len(campaign.stages)}")
    for i, s in enumerate(campaign.stages, 1):
        print(f"    {dim(str(i)+'.')} {s.class_name} ({s.module_path.split('.')[-1]})")

    print()
    confirm = input(
        bold("Run this campaign against the configured target? [y/N]: ")
    ).strip().lower()
    if confirm != "y":
        print("  Cancelled.")
        return 0

    selected_indices = _select_stages(campaign)
    # Filter campaign stages
    campaign.stages = [campaign.stages[i-1] for i in selected_indices]

    context = Context(primary_target=target_ip)
    campaign_start = time.time()

    result = campaign.run(context, progress_callback=print_progress)

    total_duration = time.time() - campaign_start
    succeeded = sum(1 for r in result.stage_results if r.success)
    total     = len(result.stage_results)

    print(f"\n{'═'*62}")
    print(bold(cyan(f"  Campaign complete: {result.campaign_name}")))
    print(f"  Duration:          {total_duration:.2f}s   "
        + (green(f"({succeeded}/{total} stages succeeded)") if succeeded == total
            else yellow(f"({succeeded}/{total} stages succeeded)")))
    print(f"{'═'*62}\n")

    paths = save_report(result, output_dir=args.report_dir)
    print(f"  {bold('Report saved:')}")
    print(f"    Markdown → {paths['markdown']}")
    print(f"    HTML     → {paths['html']}")
    return 0 if succeeded == total else 1


# ── Entrypoint ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="MyTRE — ATT&CK-Mapped Adversary Emulation Framework"
    )
    sub = parser.add_subparsers(dest="command")

    run_p = sub.add_parser("run", help="Run a campaign from a YAML file")
    run_p.add_argument("campaign_file", help="Path to campaign YAML")
    run_p.add_argument("--target",    default=None, type=_validate_ip,
                       help="Target IP (skips prompt)")
    run_p.add_argument("--ssh-port",  default=None, type=_validate_port,
                       help="SSH port override")
    run_p.add_argument("--recv-port", default=None, type=_validate_port,
                       help="Receiver port override")
    run_p.add_argument("--report-dir", default="reports",
                       help="Output directory for reports (default: reports/)")

    args = parser.parse_args()
    if args.command == "run":
        sys.exit(cmd_run(args))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
