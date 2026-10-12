"""
core/technique.py

Defines the contract every MyTRE technique module must follow.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Tactic(str, Enum):
    RECONNAISSANCE    = "reconnaissance"
    INITIAL_ACCESS    = "initial-access"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY         = "discovery"
    LATERAL_MOVEMENT  = "lateral-movement"
    PERSISTENCE       = "persistence"
    EXFILTRATION      = "exfiltration"
    IMPACT            = "impact"


@dataclass
class TechniqueResult:
    technique_name: str
    attack_id: str
    tactic: Tactic
    success: bool
    started_at: datetime
    finished_at: datetime
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()


class Technique(ABC):
    name: str = "unnamed-technique"
    attack_id: str = "T0000"
    tactic: Tactic = Tactic.RECONNAISSANCE

    def execute(self, context: "Context") -> TechniqueResult:
        started_at = datetime.now(timezone.utc)
        try:
            success, summary, evidence = self.run(context)
            error = None
        except Exception as exc:
            success, summary, evidence = False, f"technique raised: {exc}", {}
            error = str(exc)
        finished_at = datetime.now(timezone.utc)
        return TechniqueResult(
            technique_name=self.name,
            attack_id=self.attack_id,
            tactic=self.tactic,
            success=success,
            started_at=started_at,
            finished_at=finished_at,
            summary=summary,
            evidence=evidence,
            error=error,
        )

    @abstractmethod
    def run(self, context: "Context") -> tuple[bool, str, dict[str, Any]]:
        raise NotImplementedError
