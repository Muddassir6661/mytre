"""
techniques/reconnaissance/service_fingerprint.py
ATT&CK: T1592 — Gather Victim Host Information
Tactic:  Reconnaissance

Connects to open ports and reads the service banner to identify what
is running (SSH version, HTTP server, FTP daemon, etc). Results are
stored in the Context host record so later stages can make smarter
decisions — e.g. only brute-forcing SSH if the banner confirms it's
actually SSH, or flagging an outdated Apache version for T1190.
"""

import socket
from typing import Any

from core.context import Context
from core.technique import Tactic, Technique

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

HTTP_PORTS = {80, 8080, 8443, 443}


def _grab_banner(host: str, port: int, timeout: float) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in HTTP_PORTS:
                s.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            try:
                return s.recv(1024).decode("utf-8", errors="replace").strip()
            except Exception:
                return None
    except Exception:
        return None


class ServiceFingerprint(Technique):
    name = "service-fingerprint"
    attack_id = "T1592"
    tactic = Tactic.RECONNAISSANCE

    def __init__(self, target: str, ports: list[int] | None = None, timeout: float = 2.0):
        self.target = target
        self.ports = ports  # if None, uses whatever Context has for this host
        self.timeout = timeout

    def run(self, context: Context) -> tuple[bool, str, dict[str, Any]]:
        host = context.get_host(self.target)
        ports_to_probe = self.ports or (host.open_ports if host else [])

        if not ports_to_probe:
            return False, f"No ports to fingerprint on {self.target} — run PortScan first", {}

        fingerprints: dict[int, dict] = {}

        for port in ports_to_probe:
            service_guess = COMMON_PORTS.get(port, "unknown")
            banner = _grab_banner(self.target, port, self.timeout)
            fingerprints[port] = {
                "service": service_guess,
                "banner": banner or "(no banner)",
            }

        if host:
            host.notes = "; ".join(
                f"{p}/{v['service']}: {v['banner'][:60]}"
                for p, v in fingerprints.items()
            )

        identified = [p for p, v in fingerprints.items() if v["banner"] != "(no banner)"]
        summary = (
            f"Fingerprinted {len(fingerprints)} port(s) on {self.target}; "
            f"got banners from {len(identified)}: {identified}"
        )
        return True, summary, {"target": self.target, "fingerprints": fingerprints}
