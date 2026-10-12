
#!/usr/bin/env python3
"""MyTRE CLI entry point."""

import argparse
import ipaddress
import sys

# Terminal colours (supported by modern Windows Terminal / PowerShell)
RESET = "\033[0m"
CYAN = "\033[96m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
BOLD = "\033[1m"

BANNER = r"""
  __  __   _   _  ____   ____  _____
 |  \/  | | | | ||_  _| |  _ \| ____|
 | |\/| | | |_| |  | |  | |_) |  _|
 | |  | | |_   _|  |  |  _ <| |___
 |_|  |_|   |_|   |_|  |_| \_\_____|

 MyTRE — ATT&CK-Mapped Adversary Emulation Framework
 Authorized use only. Test only systems you own or have
 explicit written permission to assess.
"""


def ask_ip(prompt: str, default: str | None = None) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        value = input(f"{prompt}{suffix}: ").strip() or (default or "")
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            print("Enter a valid IPv4 or IPv6 address.")


def ask_port(prompt: str, default: int) -> int:
    while True:
        value = input(f"{prompt} [{default}]: ").strip()
        if not value:
            return default
        try:
            port = int(value)
            if 1 <= port <= 65535:
                return port
        except ValueError:
            pass
        print("Enter a port number from 1 to 65535.")


def cmd_run(args: argparse.Namespace) -> int:
    from core.campaign import Campaign, CampaignLoadError
    from core.context import Context
    from reporting.report_generator import save_report

    print(f"{BOLD}{CYAN}{BANNER}{RESET}")
    print(f"{BLUE}[*]{RESET} Loading campaign: {args.campaign_file}")

    try:
        # Load once to inspect the campaign text for interactive placeholders.
        with open(args.campaign_file, "r", encoding="utf-8-sig") as f:
            campaign_text = f.read()

        variables = {}
        uses_target = "${TARGET_IP}" in campaign_text
        uses_ssh_port = "${SSH_PORT}" in campaign_text
        uses_receiver_port = "${RECEIVER_PORT}" in campaign_text

        if uses_target:
            target = args.target or ask_ip("Target IP")
            # Validate even when supplied with --target.
            target = str(ipaddress.ip_address(target))
            variables["TARGET_IP"] = target

        if uses_ssh_port:
            variables["SSH_PORT"] = ask_port("SSH port", 22)

        if uses_receiver_port:
            variables["RECEIVER_PORT"] = ask_port("Receiver port", 8081)

        campaign = Campaign.from_yaml(args.campaign_file, variables=variables)

    except (OSError, ValueError, CampaignLoadError) as exc:
        print(f"[!] Failed to load campaign/configuration: {exc}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Run cancelled.")
        return 130

    primary_target = variables.get("TARGET_IP", args.target)
    context = Context(primary_target=primary_target)

    print(f"[*] Campaign: {campaign.name}")
    print(f"[*] Stages:   {len(campaign.stages)}")
    if primary_target:
        print(f"[*] Target:   {primary_target}")
    if "SSH_PORT" in variables:
        print(f"[*] SSH port: {variables['SSH_PORT']}")
    if "RECEIVER_PORT" in variables:
        print(f"[*] Receiver port: {variables['RECEIVER_PORT']}")

    confirm = input("\nRun this campaign against the configured target? [y/N]: ").strip().lower()
    if confirm not in {"y", "yes"}:
        print("[*] Run cancelled before any stages executed.")
        return 0

    print(f"\n{BOLD}{CYAN}[*] Starting run...{RESET}\n")
    result = campaign.run(context)

    print(f"\n{'=' * 60}")
    print(f"  Campaign complete: {result.campaign_name}")
    print(f"  Duration:          {result.duration_seconds:.2f}s")
    print(f"{'=' * 60}")
    for i, r in enumerate(result.stage_results, 1):
        if r.success:
            status = f"{GREEN}✔ SUCCESS{RESET}"
        else:
            status = f"{RED}✘ FAILED{RESET}"

        print(
            f"  {status}  Stage {i}: "
            f"{BOLD}{r.technique_name}{RESET} "
            f"({r.attack_id}) — {r.summary}"
        )
    print(f"{'=' * 60}\n")

    paths = save_report(result, output_dir=args.report_dir)
    print("[*] Report saved:")
    print(f"    Markdown -> {paths['markdown']}")
    print(f"    HTML     -> {paths['html']}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="MyTRE — ATT&CK-Mapped Adversary Emulation Framework"
    )
    sub = parser.add_subparsers(dest="command")

    run_p = sub.add_parser("run", help="Run a campaign from a YAML file")
    run_p.add_argument("campaign_file", help="Path to campaign YAML")
    run_p.add_argument("--target", default=None, help="Provide target IP without prompting")
    run_p.add_argument("--report-dir", default="reports", help="Output directory for reports")

    args = parser.parse_args()

    if args.command == "run":
        sys.exit(cmd_run(args))
    parser.print_help()
    sys.exit(0)


if __name__ == "__main__":
    main()
