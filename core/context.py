"""
core/context.py

The Context is the shared scratchpad passed through every stage of a
campaign. A reconnaissance stage can record hosts it found; a
credential-access stage can record creds it harvested; a
lateral-movement stage can then read those creds to decide where and
how to pivot. Without this, each technique would be an island and
"campaign" would just mean "things that happened to run one after
another."

Design intent: Context stores structured, namespaced data rather than
a free-for-all dict, so techniques declare what they're reading and
writing, and a report or a future technique doesn't have to guess at
key names scattered across the codebase.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Host:
    """A discovered or configured target host."""
    address: str
    open_ports: list[int] = field(default_factory=list)
    notes: str = ""


@dataclass
class Credential:
    """A credential discovered during the campaign."""
    username: str
    password: str | None = None
    key_path: str | None = None
    source_technique: str = ""   # which technique found this
    valid_on: list[str] = field(default_factory=list)  # host addresses


@dataclass
class StagedFile:
    """A file staged for exfiltration (or noted as a target for it)."""
    path: str
    description: str = ""


class Context:
    """
    Mutable shared state for one campaign run.

    Techniques read from and write to a Context instance via the
    typed helper methods below, rather than touching raw attributes
    directly, so the data model has one place to evolve.
    """

    def __init__(self, primary_target: str | None = None):
        self.primary_target = primary_target
        self.hosts: dict[str, Host] = {}
        self.credentials: list[Credential] = []
        self.staged_files: list[StagedFile] = []
        self.extra: dict[str, Any] = {}  # escape hatch for one-off data

    # --- hosts -----------------------------------------------------

    def add_host(self, address: str, open_ports: list[int] | None = None, notes: str = "") -> Host:
        host = self.hosts.get(address)
        if host is None:
            host = Host(address=address)
            self.hosts[address] = host
        if open_ports:
            host.open_ports = sorted(set(host.open_ports) | set(open_ports))
        if notes:
            host.notes = notes
        return host

    def get_host(self, address: str) -> Host | None:
        return self.hosts.get(address)

    # --- credentials -------------------------------------------------

    def add_credential(self, username: str, password: str | None = None,
                        key_path: str | None = None, source_technique: str = "",
                        valid_on: str | None = None) -> Credential:
        cred = Credential(
            username=username,
            password=password,
            key_path=key_path,
            source_technique=source_technique,
            valid_on=[valid_on] if valid_on else [],
        )
        self.credentials.append(cred)
        return cred

    def credentials_valid_on(self, host_address: str) -> list[Credential]:
        return [c for c in self.credentials if host_address in c.valid_on]

    # --- staged files ------------------------------------------------

    def stage_file(self, path: str, description: str = "") -> StagedFile:
        staged = StagedFile(path=path, description=description)
        self.staged_files.append(staged)
        return staged
