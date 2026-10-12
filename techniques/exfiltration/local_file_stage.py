"""
techniques/exfiltration/local_file_stage.py
ATT&CK: T1074.001 — Data Staged: Local Data Staging
Tactic:  Exfiltration (staging step)

Stages explicitly configured local files in the shared Context so a
later transfer stage (HTTPExfil, FTPExfil) can pick them up.

IMPORTANT: Only stages files from an explicit 'paths' list in the
campaign YAML. Never searches the filesystem, collects arbitrary
files, or stages credentials. The staged-file inventory is auditable
from the campaign config alone.
"""

import os
from typing import Any

from core.context import Context
from core.technique import Tactic, Technique


class LocalFileStage(Technique):
    name = "local-file-stage"
    attack_id = "T1074.001"
    tactic = Tactic.EXFILTRATION

    def __init__(self, paths: list[str]):
        if not paths:
            raise ValueError("LocalFileStage requires at least one path in 'paths'")
        self.paths = paths

    def run(self, context: Context) -> tuple[bool, str, dict[str, Any]]:
        staged: list[str] = []
        missing: list[str] = []

        for path in self.paths:
            if os.path.isfile(path):
                context.stage_file(path, description="explicitly configured staged file")
                staged.append(path)
            else:
                missing.append(path)

        success = len(staged) > 0
        if missing:
            summary = (
                f"Staged {len(staged)} explicitly configured local file(s); "
                f"{len(missing)} path(s) not found: {missing}"
            )
        else:
            summary = f"Staged {len(staged)} explicitly configured local file(s)"

        return success, summary, {
            "paths_configured": self.paths,
            "staged": staged,
            "missing": missing,
        }
