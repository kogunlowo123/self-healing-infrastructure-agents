"""Alerts, incidents, diagnoses and remediation plans.

Aggregates are immutable Pydantic models; every state change produces a new
instance through a method that enforces the lifecycle state machine, so an
invalid transition cannot be persisted by accident.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from agentic_core.domain.classification import Decision, RiskLevel
from agentic_core.domain.identifiers import new_id
from agentic_core.domain.provenance import canonical_json, content_digest
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from self_healing_infrastructure_agents.domain.errors import InvalidStateError

_K8S_NAME = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
# Stack paths are relative to the Terraform root: up to four safe segments.
STACK_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,62}(/[A-Za-z0-9][A-Za-z0-9_\-]{0,62}){0,3}$"
)
PLAN_FILE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-.]{0,120}$")


# --------------------------------------------------------------------- alerts


class AlertSource(StrEnum):
    ALERTMANAGER = "alertmanager"
    CLOUDWATCH = "cloudwatch"


class AlertStatus(StrEnum):
    FIRING = "firing"
    RESOLVED = "resolved"


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "warning": 1, "critical": 2}[self.value]


class TargetKind(StrEnum):
    DEPLOYMENT = "deployment"
    NODE = "node"
    TERRAFORM_STACK = "terraform_stack"
    CLOUD_RESOURCE = "cloud_resource"


class Target(BaseModel):
    """The infrastructure object an alert is about and a remediation acts on."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: TargetKind
    name: str = Field(min_length=1, max_length=253)
    namespace: str | None = Field(default=None, max_length=63)
    cluster: str | None = Field(default=None, max_length=100)
    environment: str = Field(default="production", min_length=1, max_length=40)

    @model_validator(mode="after")
    def _shape(self) -> Target:
        if self.kind in {TargetKind.DEPLOYMENT, TargetKind.NODE} and not _K8S_NAME.fullmatch(
            self.name
        ):
            raise ValueError(f"invalid Kubernetes object name {self.name!r}")
        if self.kind is TargetKind.DEPLOYMENT:
            if not self.namespace or not _K8S_NAME.fullmatch(self.namespace):
                raise ValueError("deployment targets need a valid namespace")
        elif self.kind is TargetKind.NODE and self.namespace is not None:
            raise ValueError("nodes are cluster-scoped and take no namespace")
        return self

    @property
    def ref(self) -> str:
        scope = f"{self.namespace}/" if self.namespace else ""
        cluster = f"{self.cluster}:" if self.cluster else ""
        return f"{cluster}{self.kind.value}/{scope}{self.name}"


class Alert(BaseModel):
    """A source-neutral alert. ``fingerprint`` groups repeats into one incident."""

    model_config = ConfigDict(frozen=True)

    source: AlertSource
    fingerprint: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=200)
    status: AlertStatus
    severity: Severity
    summary: str = Field(default="", max_length=2000)
    description: str = Field(default="", max_length=8000)
    labels: dict[str, str] = Field(default_factory=dict)
    annotations: dict[str, str] = Field(default_factory=dict)
    starts_at: datetime
    ends_at: datetime | None = None
    target: Target | None = None
    payload_digest: str = Field(description="sha256 of the raw notification this alert came from")
    received_at: datetime


# ------------------------------------------------------------------ diagnosis


class Evidence(BaseModel):
    """Facts gathered read-only from the environment, plus what could not be gathered."""

    model_config = ConfigDict(frozen=True)

    facts: dict[str, Any] = Field(default_factory=dict)
    observations: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    collected_at: datetime


class ActionKind(StrEnum):
    """Remediation actions. Values double as policy actions and fabric scopes."""

    RESTART_DEPLOYMENT = "k8s:restart"
    SCALE_DEPLOYMENT = "k8s:scale"
    ROLLOUT_UNDO = "k8s:rollout-undo"
    CORDON_NODE = "k8s:cordon"
    UNCORDON_NODE = "k8s:uncordon"
    TERRAFORM_APPLY = "terraform:apply"

    @property
    def target_kind(self) -> TargetKind:
        if self in {ActionKind.CORDON_NODE, ActionKind.UNCORDON_NODE}:
            return TargetKind.NODE
        if self is ActionKind.TERRAFORM_APPLY:
            return TargetKind.TERRAFORM_STACK
        return TargetKind.DEPLOYMENT


class ActionSpec(BaseModel):
    """What to do, to what, and why."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ActionKind
    target: Target
    replicas: int | None = Field(default=None, ge=0, le=1000, description="k8s:scale only")
    plan_file: str | None = Field(
        default=None, max_length=255, description="terraform:apply only; saved plan file"
    )
    rollback_stack: str | None = Field(
        default=None,
        max_length=255,
        description=(
            "terraform:apply only; stack directory holding the last-known-good configuration "
            "(same backend). If the post-check fails it is planned fresh and applied only when "
            "that plan is non-destructive"
        ),
    )
    reason: str = Field(min_length=3, max_length=2000)

    @model_validator(mode="after")
    def _parameters(self) -> ActionSpec:
        if self.target.kind is not self.kind.target_kind:
            raise ValueError(f"{self.kind.value} acts on {self.kind.target_kind.value} targets")
        if (self.kind is ActionKind.SCALE_DEPLOYMENT) != (self.replicas is not None):
            raise ValueError("replicas is required for k8s:scale and only allowed there")
        is_tf = self.kind is ActionKind.TERRAFORM_APPLY
        if is_tf != (self.plan_file is not None):
            raise ValueError("plan_file is required for terraform:apply and only allowed there")
        if self.rollback_stack is not None and not is_tf:
            raise ValueError("rollback_stack is only allowed for terraform:apply")
        if self.plan_file is not None and not PLAN_FILE_PATTERN.fullmatch(self.plan_file):
            raise ValueError("plan_file must be a bare file name inside the stack directory")
        for stack in (self.target.name if is_tf else None, self.rollback_stack):
            if stack is not None and not STACK_PATTERN.fullmatch(stack):
                raise ValueError(f"invalid Terraform stack path {stack!r}")
        if is_tf and self.rollback_stack == self.target.name:
            raise ValueError("rollback_stack must differ from the stack being changed")
        return self


class Hypothesis(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    title: str
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: tuple[str, ...] = ()
    action: ActionSpec | None = None


class Diagnosis(BaseModel):
    model_config = ConfigDict(frozen=True)

    playbook_id: str | None
    playbook_version: str | None
    hypotheses: tuple[Hypothesis, ...] = ()
    selected: Hypothesis | None = None
    evidence: Evidence
    summary: str
    narrative: str | None = Field(
        default=None, description="Advisory model-written summary; never drives actions"
    )
    escalate: bool = Field(description="True when a human must take over")


# ----------------------------------------------------------- terraform review


class ChangeAction(StrEnum):
    NO_OP = "no-op"
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    REPLACE = "replace"


class ResourceChange(BaseModel):
    model_config = ConfigDict(frozen=True)

    address: str
    type: str
    provider: str
    action: ChangeAction
    stateful: bool
    security_sensitive: bool
    changed_attributes: tuple[str, ...] = ()
    replace_paths: tuple[str, ...] = ()
    protection_disabled: tuple[str, ...] = Field(
        default=(), description="Safety attributes this change turns off"
    )


class PlanAnalysis(BaseModel):
    """Risk view of a ``terraform show -json`` plan document."""

    model_config = ConfigDict(frozen=True)

    plan_digest: str
    format_version: str
    terraform_version: str
    applyable: bool
    errored: bool
    changes: tuple[ResourceChange, ...]
    counts: dict[str, int]
    destructive: tuple[str, ...]
    stateful_deletes: tuple[str, ...]
    stateful_replacements: tuple[str, ...]
    security_changes: tuple[str, ...]
    protection_disabled: tuple[str, ...]
    drifted: tuple[str, ...]
    blast_radius: tuple[str, ...] = Field(
        description="Changed resources plus every resource that depends on them, transitively"
    )
    risk_score: int = Field(ge=0, le=100)
    risk: RiskLevel
    findings: tuple[str, ...]


# --------------------------------------------------------- remediation plans


class PolicyOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: Decision
    matched_rules: tuple[str, ...]
    policy_name: str
    policy_version: str
    policy_digest: str
    reason: str
    evaluated_at: datetime
    facts: dict[str, Any] = Field(default_factory=dict)


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class Approval(BaseModel):
    model_config = ConfigDict(frozen=True)

    approver: str
    decision: ApprovalDecision
    comment: str
    plan_digest: str
    at: datetime


class ExecutionMode(StrEnum):
    DRY_RUN = "dry_run"
    LIVE = "live"


class ExecutionOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"


class StepResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    ok: bool
    detail: str = ""
    at: datetime


class ExecutionRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=new_id)
    mode: ExecutionMode
    actor: str
    started_at: datetime
    finished_at: datetime
    outcome: ExecutionOutcome
    steps: tuple[StepResult, ...]
    snapshot: dict[str, Any] = Field(
        default_factory=dict, description="Pre-change state used for rollback"
    )


class PlanStatus(StrEnum):
    DENIED = "denied"
    PROPOSED = "proposed"  # policy allows without approval
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"
    EXPIRED = "expired"


TERMINAL_PLAN_STATES = frozenset(
    {
        PlanStatus.DENIED,
        PlanStatus.REJECTED,
        PlanStatus.SUCCEEDED,
        PlanStatus.ROLLED_BACK,
        PlanStatus.FAILED,
        PlanStatus.EXPIRED,
    }
)

_PLAN_TRANSITIONS: dict[PlanStatus, frozenset[PlanStatus]] = {
    PlanStatus.PROPOSED: frozenset({PlanStatus.EXECUTING, PlanStatus.EXPIRED}),
    PlanStatus.AWAITING_APPROVAL: frozenset(
        {PlanStatus.APPROVED, PlanStatus.REJECTED, PlanStatus.EXPIRED}
    ),
    PlanStatus.APPROVED: frozenset({PlanStatus.EXECUTING, PlanStatus.EXPIRED}),
    PlanStatus.EXECUTING: frozenset(
        {PlanStatus.SUCCEEDED, PlanStatus.ROLLED_BACK, PlanStatus.FAILED}
    ),
}


class RemediationPlan(BaseModel):
    """A proposed remediation, its policy outcome, approvals and executions."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=new_id)
    version: int = 1
    incident_id: str | None = None
    action: ActionSpec
    requested_by: str
    created_at: datetime
    updated_at: datetime
    expires_at: datetime
    status: PlanStatus
    risk: RiskLevel
    policy: PolicyOutcome
    required_approvals: int = Field(ge=0, le=5)
    approvals: tuple[Approval, ...] = ()
    terraform: PlanAnalysis | None = None
    executions: tuple[ExecutionRecord, ...] = ()
    digest: str = ""

    @model_validator(mode="after")
    def _digest(self) -> RemediationPlan:
        expected = self.compute_digest()
        if not self.digest:
            object.__setattr__(self, "digest", expected)
        elif self.digest != expected:
            raise ValueError("plan digest does not match its reviewed content")
        return self

    def compute_digest(self) -> str:
        """Digest over everything a reviewer approves: the action and the exact plans."""
        reviewed = {
            "id": self.id,
            "action": self.action.model_dump(mode="json"),
            "terraform": self.terraform.plan_digest if self.terraform else None,
        }
        return content_digest(canonical_json(reviewed))

    @property
    def approvers(self) -> frozenset[str]:
        return frozenset(
            a.approver for a in self.approvals if a.decision is ApprovalDecision.APPROVE
        )

    def transition(self, target: PlanStatus, *, at: datetime) -> RemediationPlan:
        if target not in _PLAN_TRANSITIONS.get(self.status, frozenset()):
            raise InvalidStateError(f"plan cannot move from {self.status} to {target}")
        return self.model_copy(
            update={"status": target, "updated_at": at, "version": self.version + 1}
        )

    def with_approval(self, approval: Approval) -> RemediationPlan:
        status = self.status
        if approval.decision is ApprovalDecision.REJECT:
            status = PlanStatus.REJECTED
        elif len(self.approvers | {approval.approver}) >= self.required_approvals:
            status = PlanStatus.APPROVED
        return self.model_copy(
            update={
                "approvals": (*self.approvals, approval),
                "status": status,
                "updated_at": approval.at,
                "version": self.version + 1,
            }
        )

    def with_execution(self, record: ExecutionRecord) -> RemediationPlan:
        return self.model_copy(
            update={
                "executions": (*self.executions, record),
                "updated_at": record.finished_at,
                "version": self.version + 1,
            }
        )


# ------------------------------------------------------------------ incidents


class IncidentStatus(StrEnum):
    OPEN = "open"
    DIAGNOSED = "diagnosed"
    REMEDIATING = "remediating"
    ESCALATED = "escalated"
    RESOLVED = "resolved"


class Incident(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str = Field(default_factory=new_id)
    version: int = 1
    fingerprint: str
    title: str
    severity: Severity
    status: IncidentStatus
    target: Target | None
    alerts: tuple[Alert, ...] = Field(min_length=1)
    occurrences: int = 1
    diagnosis: Diagnosis | None = None
    plan_ids: tuple[str, ...] = ()
    opened_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None
    resolution: str | None = None

    @field_validator("alerts")
    @classmethod
    def _bounded(cls, alerts: tuple[Alert, ...]) -> tuple[Alert, ...]:
        # Keep the first notification and the latest ones; repeats only bump occurrences.
        return alerts if len(alerts) <= 20 else (alerts[0], *alerts[-19:])

    @property
    def is_open(self) -> bool:
        return self.status is not IncidentStatus.RESOLVED

    def _update(self, at: datetime, **changes: Any) -> Incident:
        return self.model_copy(update={**changes, "updated_at": at, "version": self.version + 1})

    def repeat(self, alert: Alert) -> Incident:
        severity = alert.severity if alert.severity.rank > self.severity.rank else self.severity
        return self._update(
            alert.received_at,
            alerts=self._bounded((*self.alerts, alert)),
            occurrences=self.occurrences + 1,
            severity=severity,
        )

    def diagnosed(self, diagnosis: Diagnosis, *, at: datetime) -> Incident:
        if not self.is_open:
            raise InvalidStateError("resolved incidents are not re-diagnosed")
        status = IncidentStatus.ESCALATED if diagnosis.escalate else IncidentStatus.DIAGNOSED
        return self._update(at, diagnosis=diagnosis, status=status)

    def with_plan(self, plan_id: str, *, at: datetime) -> Incident:
        return self._update(at, plan_ids=(*self.plan_ids, plan_id))

    def remediating(self, *, at: datetime) -> Incident:
        if not self.is_open:
            raise InvalidStateError("incident is already resolved")
        return self._update(at, status=IncidentStatus.REMEDIATING)

    def escalated(self, reason: str, *, at: datetime) -> Incident:
        if not self.is_open:
            raise InvalidStateError("incident is already resolved")
        return self._update(at, status=IncidentStatus.ESCALATED, resolution=reason)

    def resolved(self, reason: str, *, at: datetime) -> Incident:
        if not self.is_open:
            raise InvalidStateError("incident is already resolved")
        return self._update(at, status=IncidentStatus.RESOLVED, resolved_at=at, resolution=reason)


# ------------------------------------------------------------------ principals


class PrincipalKind(StrEnum):
    AGENT = "agent"
    USER = "user"
    SERVICE = "service"


class Principal(BaseModel):
    """An authenticated caller, or this service acting on its own behalf."""

    model_config = ConfigDict(frozen=True)

    subject: str
    kind: PrincipalKind
    scopes: frozenset[str] = frozenset()
    roles: frozenset[str] = frozenset()
    requires_approval: bool = Field(
        default=False,
        description="The caller's own authorization said a human must approve its requests",
    )


# --------------------------------------------------------------------- scopes

REMEDIATION_SCOPES = frozenset(
    {
        "incidents:read",
        "alerts:diagnose",
        "terraform:analyze",
        "remediation:read",
        "remediation:propose",
        "remediation:dry-run",
        "remediation:execute",
    }
)


def scope_matches(scope: str, action: str) -> bool:
    """Exact match, or a trailing ``:*`` wildcard segment (``remediation:*``)."""
    if scope == action:
        return True
    return scope.endswith(":*") and action.startswith(scope[:-1])


def expand_scopes(scopes: frozenset[str]) -> frozenset[str]:
    """Granted scopes plus every known scope a wildcard grants."""
    implied = {
        known for known in REMEDIATION_SCOPES if any(scope_matches(s, known) for s in scopes)
    }
    return scopes | implied
