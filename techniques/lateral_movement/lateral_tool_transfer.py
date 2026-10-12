"""
techniques/lateral_movement/lateral_tool_transfer.py
ATT&CK: T1570 — Lateral Tool Transfer
Tactic:  Lateral Movement

Transfers a file to the pivot host over SSH (SFTP). In a real
engagement this would be a post-exploit tool, a script, or a payload.
In MyTRE it transfers a configurable local file (defaults to a
benign marker file) and verifies it landed correctly. Records the
transferred file path in Context staged_files for use by exfiltration.
"""

import os
import tempfile
import paramiko
from typing import Any

from core.context import Context
from core.technique import Tactic, Technique


class LateralToolTransfer(Technique):
    name = "lateral-tool-transfer"
    attack_id = "T1570"
    tactic = Tactic.LATERAL_MOVEMENT

    def __init__(
        self,
        target: str,
        port: int = 22,
        username: str | None = None,
        password: str | None = None,
        local_file: str | None = None,
        remote_path: str = "/tmp/mytre_marker.txt",
        timeout: float = 10.0,
    ):
        self.target = target
        self.port = port
        self.username = username
        self.password = password
        self.local_file = local_file
        self.remote_path = remote_path
        self.timeout = timeout

    def _resolve_creds(self, context: Context) -> tuple[str | None, str | None]:
        if self.username and self.password:
            return self.username, self.password
        creds = context.credentials_valid_on(self.target) or context.credentials
        if creds:
            return creds[0].username, creds[0].password
        return None, None

    def _ensure_local_file(self) -> str:
        """Use provided file or create a benign marker file."""
        if self.local_file and os.path.isfile(self.local_file):
            return self.local_file
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="mytre_"
        )
        tmp.write("MyTRE lateral tool transfer marker — authorized test\n")
        tmp.close()
        return tmp.name

    def run(self, context: Context) -> tuple[bool, str, dict[str, Any]]:
        username, password = self._resolve_creds(context)
        if not username or not password:
            return False, "No SSH credentials in Context for LateralToolTransfer", {}

        local_path = self._ensure_local_file()
        local_size = os.path.getsize(local_path)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                self.target, port=self.port, username=username, password=password,
                timeout=self.timeout, look_for_keys=False, allow_agent=False,
            )
            sftp = client.open_sftp()
            sftp.put(local_path, self.remote_path)

            # Verify it landed
            remote_stat = sftp.stat(self.remote_path)
            sftp.close()
            client.close()

            context.stage_file(
                self.remote_path,
                description=f"Transferred to {self.target} via SFTP"
            )

            summary = (
                f"Transferred {local_size} bytes to {self.target}:{self.remote_path} "
                f"(remote size confirmed: {remote_stat.st_size} bytes)"
            )
            return True, summary, {
                "target": self.target,
                "local_file": local_path,
                "remote_path": self.remote_path,
                "local_size_bytes": local_size,
                "remote_size_bytes": remote_stat.st_size,
            }
        except Exception as exc:
            return False, f"File transfer failed: {exc}", {}
        finally:
            client.close()
