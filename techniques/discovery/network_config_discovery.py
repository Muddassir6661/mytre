"""
techniques/discovery/network_config_discovery.py
ATT&CK: T1016 — System Network Configuration Discovery
Tactic:  Discovery

Collects network configuration from the target over SSH — interfaces,
routing table, open ports, DNS config, ARP cache. Useful for
understanding pivot opportunities and adjacent hosts.
"""

import paramiko
from typing import Any
from core.context import Context
from core.technique import Tactic, Technique

COMMANDS = [
    "ip addr show 2>/dev/null || ifconfig 2>/dev/null | head -30",
    "ip route show 2>/dev/null || route -n 2>/dev/null",
    "ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null | head -20",
    "cat /etc/resolv.conf 2>/dev/null",
    "arp -n 2>/dev/null | head -20",
    "cat /etc/hosts | grep -v '^#' | grep -v '^$'",
]


class NetworkConfigDiscovery(Technique):
    name = "network-config-discovery"
    attack_id = "T1016"
    tactic = Tactic.DISCOVERY

    def __init__(self, target: str, port: int = 22,
                 username: str | None = None, password: str | None = None,
                 timeout: float = 10.0):
        self.target = target
        self.port = int(port)
        self.username = username
        self.password = password
        self.timeout = timeout

    def _resolve_creds(self, context: Context):
        if self.username and self.password:
            return self.username, self.password
        creds = context.credentials_valid_on(self.target) or context.credentials
        if creds:
            return creds[0].username, creds[0].password
        return None, None

    def run(self, context: Context) -> tuple[bool, str, dict[str, Any]]:
        username, password = self._resolve_creds(context)
        if not username or not password:
            return False, "No SSH credentials in Context", {}

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(self.target, port=self.port, username=username,
                           password=password, timeout=self.timeout,
                           look_for_keys=False, allow_agent=False)
            findings = {}
            for cmd in COMMANDS:
                _, stdout, _ = client.exec_command(cmd)
                out = stdout.read().decode("utf-8", errors="replace").strip()
                if out:
                    findings[cmd] = out[:800]

            # Surface any discovered hosts from ARP into Context
            arp_out = findings.get("arp -n 2>/dev/null | head -20", "")
            for line in arp_out.splitlines():
                parts = line.split()
                if parts and parts[0][0].isdigit():
                    context.add_host(parts[0], notes="discovered via ARP on pivot host")

            client.close()
            summary = f"Network config discovery on {self.target}: {len(findings)} data point(s) collected"
            return True, summary, {"target": self.target, "findings": findings}
        except Exception as exc:
            return False, f"Network discovery failed: {exc}", {}
        finally:
            try: client.close()
            except Exception: pass
