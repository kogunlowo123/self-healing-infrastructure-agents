"""Versioned diagnosis playbooks.

A playbook matches alerts, names the evidence collectors to run, and lists
hypotheses. A hypothesis holds when all of its ``when`` conditions hold over
the collected facts (agentic-core policy conditions on ``resource.*``); each
``supporting`` condition that also holds adds to its confidence. The
highest-confidence hypothesis at or above the playbook's threshold is
selected. Its action template becomes a concrete ActionSpec; a hypothesis
without an action escalates to a human with its escalation note.
"""

from __future__ import annotations

import fnmatch
import math
from pathlib import Path
from typing import Any, Literal

import yaml
from agentic_core.policy import Condition
from pydantic import BaseModel, ConfigDict, Field, field_validator

from self_healing_infrastructure_agents.domain.models import (
    ActionKind,
    Alert,
    TargetKind,
)

Collector = Literal["deployment", "pods", "rollout", "node", "alert"]


class Match(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    alertnames: tuple[str, ...] = Field(min_length=1, description="Glob patterns")
    target_kind: TargetKind | None = None
    labels: dict[str, str] = Field(default_factory=dict)

    def matches(self, alert: Alert) -> bool:
        if not any(fnmatch.fnmatchcase(alert.name, p) for p in self.alertnames):
            return False
        if self.target_kind is not None and (
            alert.target is None or alert.target.kind is not self.target_kind
        ):
            return False
        return all(alert.labels.get(k) == v for k, v in self.labels.items())


class ScaleStrategy(BaseModel):
    """Proportional scale-out: replicas * utilization / target, bounded."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    target_utilization: float = Field(gt=0.0, le=1.0)
    max_step: float = Field(default=2.0, gt=1.0, le=3.0)
    max_replicas: int = Field(default=50, ge=1, le=1000)

    def desired(self, current: int, utilization: float) -> int | None:
        """New replica count, or None when scaling out cannot help."""
        if current < 1 or utilization <= self.target_utilization:
            return None
        proportional = math.ceil(current * utilization / self.target_utilization)
        bounded = min(proportional, math.floor(current * self.max_step), self.max_replicas)
        bounded = max(bounded, current + 1)
        return bounded if bounded <= self.max_replicas else None


class ActionTemplate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ActionKind
    scale: ScaleStrategy | None = None

    @field_validator("kind")
    @classmethod
    def _automatable(cls, kind: ActionKind) -> ActionKind:
        if kind is ActionKind.TERRAFORM_APPLY:
            raise ValueError("terraform:apply needs a reviewed plan; playbooks cannot template it")
        return kind


class HypothesisSpec(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1)
    title: str = Field(min_length=3)
    confidence: float = Field(ge=0.0, le=0.99)
    when: tuple[Condition, ...] = Field(min_length=1)
    supporting: tuple[Condition, ...] = ()
    action: ActionTemplate | None = None
    escalation: str | None = None

    def holds(self, facts: dict[str, Any]) -> bool:
        return all(c.evaluate(facts) for c in self.when)

    def score(self, facts: dict[str, Any]) -> float:
        support = sum(1 for c in self.supporting if c.evaluate(facts))
        return round(min(0.99, self.confidence + 0.05 * support), 4)


class Playbook(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1)
    title: str
    description: str = ""
    match: Match
    collectors: tuple[Collector, ...] = ()
    min_confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    hypotheses: tuple[HypothesisSpec, ...] = Field(min_length=1)


class PlaybookSet(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    version: str
    playbooks: tuple[Playbook, ...]

    @field_validator("playbooks")
    @classmethod
    def _unique(cls, playbooks: tuple[Playbook, ...]) -> tuple[Playbook, ...]:
        ids = [p.id for p in playbooks]
        if len(ids) != len(set(ids)):
            raise ValueError("playbook ids must be unique")
        return playbooks

    @classmethod
    def from_file(cls, path: Path) -> PlaybookSet:
        return cls.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))

    def select(self, alert: Alert) -> Playbook | None:
        return next((p for p in self.playbooks if p.match.matches(alert)), None)
