"""Load one known lab SSH credential into Context without logging its password."""

import getpass
from typing import Any

from core.context import Context
from core.technique import Tactic, Technique


class KnownSSHCredential(Technique):
    name = "known-ssh-credential"
    attack_id = "T1078"
    tactic = Tactic.CREDENTIAL_ACCESS

    def __init__(self, target: str, username: str):
        self.target = target
        self.username = username

    def run(self, context: Context) -> tuple[bool, str, dict[str, Any]]:
        password = getpass.getpass(
            f"Enter the known SSH password for {self.username}@{self.target}: "
        )

        if not password:
            return False, "No credential entered", {"target": self.target}

        context.add_credential(
            username=self.username,
            password=password,
            source_technique=self.name,
            valid_on=self.target,
        )

        return True, "Known SSH credential loaded into Context", {
            "target": self.target,
            "username": self.username,
            "credential_loaded": True,
        }
