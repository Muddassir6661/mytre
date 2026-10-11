"""
core/campaign.py

The Campaign engine ties everything together: it loads a YAML
campaign definition, instantiates the listed techniques in order,
runs each one against a shared Context, and collects the resulting
TechniqueResults for the report generator.

This module deliberately knows nothing about what any individual
technique does — it only knows the Technique interface from
core/technique.py. That separation is what lets you add a new
technique (a new attacks/*.py file) without ever touching this file.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import importlib
import yaml

from core.context import Context
from core.technique import Technique, TechniqueResult


@dataclass
class StageSpec:
    """One entry from a campaign YAML file, before it's instantiated."""
    module_path: str              # e.g. "techniques.reconnaissance.port_scan"
    class_name: str                # e.g. "PortScan"
    params: dict = field(default_factory=dict)
    continue_on_failure: bool = True


@dataclass
class CampaignResult:
    """Everything a completed campaign run produced."""
    campaign_name: str
    started_at: datetime
    finished_at: datetime
    context: Context
    stage_results: list[TechniqueResult]

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()


class CampaignLoadError(Exception):
    """Raised when a campaign YAML file is malformed or a stage can't be resolved."""


class Campaign:
    def __init__(self, name: str, stages: list[StageSpec]):
        self.name = name
        self.stages = stages

    @classmethod
    def from_yaml(cls, path: str) -> "Campaign":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if "campaign" not in data or "stages" not in data:
            raise CampaignLoadError(
                f"{path}: campaign file must define 'campaign' (name) and 'stages' (list)"
            )

        stages = []
        for i, raw_stage in enumerate(data["stages"]):
            if "module" not in raw_stage:
                raise CampaignLoadError(f"{path}: stage #{i} is missing 'module'")
            # "module" is written as e.g. "reconnaissance.port_scan:PortScan"
            # (dotted path, colon, class name) to keep YAML terse.
            module_ref, _, class_name = raw_stage["module"].partition(":")
            if not class_name:
                raise CampaignLoadError(
                    f"{path}: stage #{i} 'module' must be 'package.module:ClassName' "
                    f"(got {raw_stage['module']!r})"
                )
            stages.append(StageSpec(
                module_path=f"techniques.{module_ref}",
                class_name=class_name,
                params=raw_stage.get("params", {}),
                continue_on_failure=raw_stage.get("continue_on_failure", True),
            ))

        return cls(name=data["campaign"], stages=stages)

    @staticmethod
    def _instantiate(stage: StageSpec) -> Technique:
        try:
            module = importlib.import_module(stage.module_path)
            technique_cls = getattr(module, stage.class_name)
        except (ImportError, AttributeError) as exc:
            raise CampaignLoadError(
                f"could not load {stage.class_name} from {stage.module_path}: {exc}"
            ) from exc
        return technique_cls(**stage.params)

    def run(self, context: Context) -> CampaignResult:
        started_at = datetime.now(timezone.utc)
        results: list[TechniqueResult] = []

        for stage in self.stages:
            technique = self._instantiate(stage)
            result = technique.execute(context)
            results.append(result)

            if not result.success and not stage.continue_on_failure:
                break

        finished_at = datetime.now(timezone.utc)
        return CampaignResult(
            campaign_name=self.name,
            started_at=started_at,
            finished_at=finished_at,
            context=context,
            stage_results=results,
        )
