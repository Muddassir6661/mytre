"""
techniques/reconnaissance/port_scan.py
ATT&CK: T1046 — Network Service Discovery
Tactic:  Reconnaissance

Scans a target host for open TCP ports using a basic connect scan
(no raw packets, no root required). Records open ports in Context
so later stages (e.g. SSH brute force) can use them.
"""

import socket
from typing import Any

from core.context import Context
from core.technique import Tactic, Technique


class PortScan(Technique):
    name = "port-scan"
    attack_id = "T1046"
    tactic = Tactic.RECONNAISSANCE

    def __init__(self, target: str, port_range: str = "1-1024", timeout: float = 0.5):
        self.target = target
        self.start_port, self.end_port = self._parse_range(port_range)
        self.timeout = timeout

    @staticmethod
    def _parse_range(port_range: str) -> tuple[int, int]:
        parts = port_range.split("-")
        if len(parts) != 2:
            raise ValueError(f"port_range must be 'start-end', got {port_range!r}")
        return int(parts[0]), int(parts[1])

    def run(self, context: Context) -> tuple[bool, str, dict[str, Any]]:
        open_ports: list[int] = []

        for port in range(self.start_port, self.end_port + 1):
            print(f"[*] Scanning port {port}... ", end="\r")
            try:
                with socket.create_connection((self.target, port), timeout=self.timeout):
                    open_ports.append(port)
            except (ConnectionRefusedError, OSError, TimeoutError):
                continue

        if open_ports:
            context.add_host(self.target, open_ports=open_ports)

        success = len(open_ports) > 0
        summary = (
            f"Found {len(open_ports)} open port(s) on {self.target}: {open_ports}"
            if success
            else f"No open ports found on {self.target} in range {self.start_port}-{self.end_port}"
        )

        return success, summary, {
            "target": self.target,
            "ports_scanned": f"{self.start_port}-{self.end_port}",
            "open_ports": open_ports,
        }
