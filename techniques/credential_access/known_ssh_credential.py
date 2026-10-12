"""
techniques/credential_access/known_ssh_credential.py
ATT&CK: T1078 — Valid Accounts
Tactic:  Credential Access

Validates a known SSH credential entered interactively at runtime
using getpass (hidden input). No password is ever stored in YAML,
result dicts, logs, or reports. Useful for known-credential
scenarios or when you don't need a full brute-force run.
"""

import getpass
import paramiko
from typing import Any

from core.context import Context
from core.technique import Tactic, Technique


class KnownSSHCredential(Technique):
    name = "known-ssh-credential"
    attack_id = "T1078"
    tactic = Tactic.CREDENTIAL_ACCESS

    def __init__(
        self,
        target: str,
        port: int = 22,
        username: str = "root",
        timeout: float = 8.0,
    ):
        self.target = target
        self.port = int(port)
        self.username = username
        self.timeout = timeout

    def run(self, context: Context) -> tuple[bool, str, dict[str, Any]]:
        # Hidden prompt — password never touches a variable beyond this scope
        try:
            password = getpass.getpass(
                prompt=f"[MyTRE] SSH password for {self.username}@{self.target}: "
            )
        except (EOFError, KeyboardInterrupt):
            return False, "Password entry cancelled", {}

        if not password:
            return False, "No password entered", {}

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                self.target,
                port=self.port,
                username=self.username,
                password=password,
                timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            client.close()
            # Store in Context only — never in result
            context.add_credential(
                username=self.username,
                password=password,
                source_technique=self.name,
                valid_on=self.target,
            )
            return True, (
                f"SSH credential validated for {self.username}@{self.target}:{self.port}"
            ), {
                "target": self.target,
                "port": self.port,
                "username": self.username,
                "credential_found": True,
            }
        except paramiko.AuthenticationException:
            return False, (
                f"Authentication failed for {self.username}@{self.target}:{self.port}"
            ), {
                "target": self.target,
                "port": self.port,
                "username": self.username,
                "credential_found": False,
            }
        except Exception as exc:
            return False, f"Connection error: {exc}", {}
        finally:
            try:
                client.close()
            except Exception:
                pass
