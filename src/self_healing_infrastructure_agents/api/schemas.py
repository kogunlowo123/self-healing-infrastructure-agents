"""Request and response bodies for the HTTP API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from self_healing_infrastructure_agents.domain.models import (
    ActionSpec,
    ApprovalDecision,
    Incident,
    RemediationPlan,
)


class ProposeRemediation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: ActionSpec
    incident_id: str | None = Field(default=None, max_length=64)


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: ApprovalDecision
    plan_digest: str = Field(
        pattern=r"^sha256:[0-9a-f]{64}$", description="Digest of the plan version reviewed"
    )
    comment: str = Field(min_length=3, max_length=2000)


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dry_run: bool = Field(
        default=True, description="Server-side dry run unless explicitly set to false"
    )


class AnalyzePlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan: dict[str, Any] = Field(description="Output of `terraform show -json <planfile>`")


class IncidentList(BaseModel):
    items: list[Incident]
    limit: int
    offset: int


class PlanList(BaseModel):
    items: list[RemediationPlan]
    limit: int
    offset: int


class SnsAck(BaseModel):
    status: str
    accepted: int = 0
    opened: list[str] = Field(default_factory=list)
    resolved: list[str] = Field(default_factory=list)


class OAuthError(BaseModel):
    error: str
    error_description: str
