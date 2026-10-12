"""
techniques/discovery/file_directory_discovery.py
ATT&CK: T1083 — File and Directory Discovery
Tactic:  Discovery

Over an established SSH session, enumerates interesting directories
and files on the target host — home dirs, web roots, common config
locations. Requires prior SSH credential in Context.
"""

import paramiko
from typing import Any
from core.context import Context
from core.technique import Tactic, Technique

DISCOVERY_COMMANDS = [
    "ls -la /home/",
    "ls -la /var/www/html/ 2>/dev/null || echo NOT_FOUND",
    "ls -la /etc/ | grep -E '\\.(conf|cfg|ini)$' | head -10",
    "find /tmp /var/tmp -maxdepth 1 -type f 2>/dev/null | head -10",
    "ls -la ~/.ssh/ 2>/dev/null || echo NOT_FOUND",
    "find /var/www -name '*.php' -maxdepth 3 2>/dev/null | head -10",
]


class FileDirectoryDiscovery(Technique):
    name = "file-directory-discovery"
    attack_id = "T1083"
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
            results = {}
            for cmd in DISCOVERY_COMMANDS:
                _, stdout, _ = client.exec_command(cmd)
                out = stdout.read().decode("utf-8", errors="replace").strip()
                if out and "NOT_FOUND" not in out:
                    results[cmd] = out[:500]
            client.close()
            summary = f"File/directory discovery on {self.target}: {len(results)} location(s) enumerated"
            return True, summary, {"target": self.target, "findings": results}
        except Exception as exc:
            return False, f"File discovery failed: {exc}", {}
        finally:
            try: client.close()
            except Exception: pass
