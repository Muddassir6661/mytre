"""
core/technique.py

Defines the contract every MyTRE technique module must follow.
Every stage of a campaign (recon, credential access, lateral movement,
exfiltration, etc.) is a Technique subclass. The Campaign engine only
ever talks to this interface — it never knows the specifics of how a
port scan differs from an SSH pivot.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Tactic(str, Enum):
    """MITRE ATT&CK tactic categories relevant to MyTRE's scope."""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial-access"
    CREDENTIAL_ACCESS = "credential-access"
    LATERAL_MOVEMENT = "lateral-movement"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class TechniqueResult:
    """
    The structured outcome of running one technique.

    This is the atomic unit the report generator and the campaign
    Context both consume. Nothing downstream should ever need to
    reach back into a technique's internals — everything they need
    must be captured here.
    """
    technique_name: str
    attack_id: str              # e.g. "T1595" (MITRE technique ID)
    tactic: Tactic
    success: bool
    started_at: datetime
    finished_at: datetime
    summary: str                 # one-line human-readable outcome
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()


class Technique(ABC):
    """
    Base class for every MyTRE technique module.

    Subclasses declare their ATT&CK metadata as class attributes and
    implement `run()`. The campaign engine calls `execute()`, which
    wraps `run()` with timing and consistent error handling so no
    individual module has to reimplement that bookkeeping.
    """

    # Subclasses must override these.
    name: str = "unnamed-technique"
    attack_id: str = "T0000"
    tactic: Tactic = Tactic.RECONNAISSANCE

    def execute(self, context: "Context") -> TechniqueResult:
        started_at = datetime.now(timezone.utc)
        try:
            success, summary, evidence = self.run(context)
            error = None
        except Exception as exc:  # noqa: BLE001 - deliberately broad: a
            # failed technique is a valid, expected campaign outcome,
            # not a crash. We capture it in the result instead of
            # letting it kill the whole campaign run.
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
        """
        Do the actual work.

        Returns (success, summary, evidence):
          - success: whether the technique achieved its objective
          - summary: one-line human-readable outcome for the report
          - evidence: structured data (ports found, creds harvested,
            files staged, etc.) — whatever a later stage or the
            report might need.

        Implementations should raise on genuine unexpected errors;
        execute() will catch and record them. Returning
        success=False for an expected "technique didn't work" outcome
        (e.g. brute force found no valid creds) is preferred over
        raising.
        """
        raise NotImplementedError
