"""
techniques/discovery/process_discovery.py
ATT&CK: T1057 — Process Discovery
Tactic:  Discovery

Lists running processes on the target over SSH. Helps identify
security tools, databases, and web servers for targeting or evasion.
"""

import paramiko
from typing import Any
from core.context import Context
from core.technique import Tactic, Technique

COMMANDS = [
    "ps aux --sort=-%cpu | head -20",
    "ps aux | grep -E '(apache|nginx|mysql|postgres|docker|wazuh|ssh)' | grep -v grep",
]


class ProcessDiscovery(Technique):
    name = "process-discovery"
    attack_id = "T1057"
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
                    findings[cmd] = out[:1000]
            client.close()
            summary = f"Process discovery on {self.target}: captured {len(findings)} process listing(s)"
            return True, summary, {"target": self.target, "findings": findings}
        except Exception as exc:
            return False, f"Process discovery failed: {exc}", {}
        finally:
            try: client.close()
            except Exception: pass
