"""
techniques/discovery/account_discovery.py
ATT&CK: T1087 — Account Discovery
Tactic:  Discovery

Enumerates local user accounts on the target over SSH. Identifies
privileged accounts, service accounts, and potential lateral movement
targets. Output is recorded as evidence only — no credentials stored.
"""

import paramiko
from typing import Any
from core.context import Context
from core.technique import Tactic, Technique

COMMANDS = [
    "cat /etc/passwd | grep -v nologin | grep -v false | grep -v halt | grep -v shutdown",
    "getent group sudo 2>/dev/null || grep sudo /etc/group",
    "last -n 10 2>/dev/null",
    "who 2>/dev/null",
    "id",
]


class AccountDiscovery(Technique):
    name = "account-discovery"
    attack_id = "T1087"
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
                    findings[cmd] = out[:500]
            client.close()

            # Count interactive accounts found
            passwd_output = findings.get(COMMANDS[0], "")
            accounts = [l.split(":")[0] for l in passwd_output.splitlines() if l.strip()]

            summary = (
                f"Account discovery on {self.target}: "
                f"{len(accounts)} interactive account(s) found — {accounts[:8]}"
            )
            return True, summary, {
                "target": self.target,
                "accounts": accounts,
                "findings": findings,
            }
        except Exception as exc:
            return False, f"Account discovery failed: {exc}", {}
        finally:
            try: client.close()
            except Exception: pass
