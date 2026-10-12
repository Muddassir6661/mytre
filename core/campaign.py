"""
core/campaign.py

Campaign engine with variable resolution support.
Variables like ${TARGET_IP}, ${SSH_PORT}, ${RECEIVER_PORT} in YAML
values are resolved at load time from a supplied variables dict.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import importlib
import re
import yaml

from core.context import Context
from core.technique import Technique, TechniqueResult


@dataclass
class StageSpec:
    module_path: str
    class_name: str
    params: dict = field(default_factory=dict)
    continue_on_failure: bool = True


@dataclass
class CampaignResult:
    campaign_name: str
    started_at: datetime
    finished_at: datetime
    context: Context
    stage_results: list[TechniqueResult]

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()


class CampaignLoadError(Exception):
    pass


def _resolve_value(value, variables: dict):
    """
    Recursively resolve ${VAR} placeholders in strings, lists, and dicts.
    If a string is exactly one placeholder, resolve to the variable's native
    type (e.g. an int port). Otherwise interpolate into the string.
    """
    if isinstance(value, str):
        # Whole-string single placeholder → preserve type
        single = re.fullmatch(r'\$\{(\w+)\}', value)
        if single:
            key = single.group(1)
            if key in variables:
                return variables[key]
            raise CampaignLoadError(f"Undefined variable: ${{{key}}}")
        # Embedded placeholders → interpolate as string
        def replacer(m):
            key = m.group(1)
            if key not in variables:
                raise CampaignLoadError(f"Undefined variable: ${{{key}}}")
            return str(variables[key])
        return re.sub(r'\$\{(\w+)\}', replacer, value)
    elif isinstance(value, dict):
        return {k: _resolve_value(v, variables) for k, v in value.items()}
    elif isinstance(value, list):
        return [_resolve_value(item, variables) for item in value]
    return value


class Campaign:
    def __init__(self, name: str, stages: list[StageSpec]):
        self.name = name
        self.stages = stages

    @classmethod
    def from_yaml(cls, path: str, variables: dict | None = None) -> "Campaign":
        variables = variables or {}
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if "campaign" not in data or "stages" not in data:
            raise CampaignLoadError(
                f"{path}: must define 'campaign' and 'stages'"
            )

        stages = []
        for i, raw_stage in enumerate(data["stages"]):
            if "module" not in raw_stage:
                raise CampaignLoadError(f"{path}: stage #{i} missing 'module'")
            module_ref, _, class_name = raw_stage["module"].partition(":")
            if not class_name:
                raise CampaignLoadError(
                    f"{path}: stage #{i} 'module' must be 'package.module:ClassName'"
                )
            raw_params = raw_stage.get("params", {})
            resolved_params = _resolve_value(raw_params, variables)
            stages.append(StageSpec(
                module_path=f"techniques.{module_ref}",
                class_name=class_name,
                params=resolved_params,
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
                f"Could not load {stage.class_name} from {stage.module_path}: {exc}"
            ) from exc
        return technique_cls(**stage.params)

    def run(
        self,
        context: Context,
        progress_callback=None,
    ) -> CampaignResult:
        """
        Run all stages in order against the shared context.
        progress_callback(event: dict) is called at stage start and finish.
        """
        started_at = datetime.now(timezone.utc)
        results: list[TechniqueResult] = []
        total = len(self.stages)

        for idx, stage in enumerate(self.stages, 1):
            technique = self._instantiate(stage)

            if progress_callback:
                progress_callback({
                    "event": "stage_start",
                    "index": idx,
                    "total": total,
                    "technique_name": technique.name,
                    "attack_id": technique.attack_id,
                    "tactic": technique.tactic.value,
                })

            result = technique.execute(context)
            results.append(result)

            if progress_callback:
                progress_callback({
                    "event": "stage_end",
                    "index": idx,
                    "total": total,
                    "technique_name": technique.name,
                    "attack_id": technique.attack_id,
                    "success": result.success,
                    "summary": result.summary,
                    "duration": result.duration_seconds,
                })

            if not result.success and not stage.continue_on_failure:
                if progress_callback:
                    progress_callback({
                        "event": "campaign_aborted",
                        "index": idx,
                        "reason": result.summary,
                    })
                break

        finished_at = datetime.now(timezone.utc)
        return CampaignResult(
            campaign_name=self.name,
            started_at=started_at,
            finished_at=finished_at,
            context=context,
            stage_results=results,
        )
