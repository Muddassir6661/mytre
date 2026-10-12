"""
core/attck.py

Loads MITRE ATT&CK technique metadata so technique modules can pull
authoritative names, tactic labels, and descriptions by ID rather
than hardcoding them. Uses a lightweight local JSON bundle (no
network required at runtime) derived from the public ATT&CK STIX
dataset at https://github.com/mitre/cti.

If the bundle file isn't present, the registry falls back gracefully
to whatever the technique module itself declares — the framework
keeps running, but enrichment is skipped.
"""

import json
import os
from dataclasses import dataclass
from functools import lru_cache


BUNDLE_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "attck_techniques.json")


@dataclass(frozen=True)
class ATTCKTechnique:
    id: str          # e.g. "T1595"
    name: str         # e.g. "Active Scanning"
    tactic: str        # e.g. "reconnaissance"
    description: str   # first paragraph from ATT&CK


class ATTCKRegistry:
    """
    Lightweight lookup table for ATT&CK technique metadata.

    Usage:
        registry = ATTCKRegistry.load()
        info = registry.get("T1595")
        print(info.name, info.tactic)
    """

    def __init__(self, techniques: dict[str, ATTCKTechnique]):
        self._techniques = techniques

    @classmethod
    def load(cls) -> "ATTCKRegistry":
        path = os.path.abspath(BUNDLE_PATH)
        if not os.path.exists(path):
            return cls({})  # empty registry, fallback mode

        with open(path, "r", encoding="utf-8") as f:
            raw: list[dict] = json.load(f)

        techniques = {}
        for entry in raw:
            tech = ATTCKTechnique(
                id=entry["id"],
                name=entry["name"],
                tactic=entry.get("tactic", ""),
                description=entry.get("description", ""),
            )
            techniques[tech.id] = tech

        return cls(techniques)

    def get(self, technique_id: str) -> ATTCKTechnique | None:
        return self._techniques.get(technique_id)

    def enrich(self, technique_id: str, fallback_name: str, fallback_tactic: str) -> ATTCKTechnique:
        """Return registry data if available, or a fallback object if not."""
        entry = self.get(technique_id)
        if entry:
            return entry
        return ATTCKTechnique(
            id=technique_id,
            name=fallback_name,
            tactic=fallback_tactic,
            description="(ATT&CK bundle not loaded — description unavailable)",
        )


@lru_cache(maxsize=1)
def get_registry() -> ATTCKRegistry:
    """Module-level singleton so the bundle is only read once per process."""
    return ATTCKRegistry.load()
