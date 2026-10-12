"""Stage explicitly configured local files for a controlled lab test."""

from pathlib import Path
from typing import Any

from core.context import Context
from core.technique import Tactic, Technique


class LocalFileStage(Technique):
    name = "local-file-stage"
    attack_id = "T1074.001"
    tactic = Tactic.EXFILTRATION

    def __init__(self, paths: list[str]):
        self.paths = paths

    def run(self, context: Context) -> tuple[bool, str, dict[str, Any]]:
        staged = []
        missing = []

        for raw_path in self.paths:
            path = Path(raw_path).expanduser().resolve()

            if not path.is_file():
                missing.append(str(path))
                continue

            context.stage_file(
                str(path),
                description="Explicitly configured local lab test file",
            )
            staged.append(str(path))

        evidence = {
            "staged_files": staged,
            "missing_files": missing,
        }

        if missing:
            return False, f"{len(missing)} configured file(s) not found", evidence

        if not staged:
            return False, "No files configured for staging", evidence

        return True, f"Staged {len(staged)} explicitly configured local file(s)", evidence
