"""Ports to the outside world. Adapters live in ``integrations`` and ``infrastructure``."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from self_healing_infrastructure_agents.domain.models import (
    Incident,
    IncidentStatus,
    PlanStatus,
    RemediationPlan,
)


class Clock(Protocol):
    def now(self) -> datetime: ...


# ------------------------------------------------------------------ cluster


class DeploymentState(BaseModel):
    model_config = ConfigDict(frozen=True)

    namespace: str
    name: str
    uid: str
    resource_version: str
    generation: int
    observed_generation: int
    replicas: int
    ready_replicas: int
    updated_replicas: int
    available_replicas: int
    revision: int | None
    selector: dict[str, str]
    template: dict[str, Any]
    progress_deadline_exceeded: bool
    created_at: datetime | None = None

    @property
    def rollout_complete(self) -> bool:
        return (
            self.observed_generation >= self.generation
            and self.updated_replicas == self.replicas
            and self.ready_replicas == self.replicas
            and self.available_replicas == self.replicas
        )


class ReplicaSetState(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    revision: int
    owner_uid: str | None
    template: dict[str, Any]
    created_at: datetime | None = None


class ContainerTermination(BaseModel):
    model_config = ConfigDict(frozen=True)

    reason: str
    exit_code: int


class PodState(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    phase: str
    ready: bool
    restart_count: int
    waiting_reasons: tuple[str, ...] = ()
    last_terminations: tuple[ContainerTermination, ...] = ()
    started_at: datetime | None = None
    node: str | None = None


class NodeState(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    resource_version: str
    ready: bool
    unschedulable: bool
    pressure: tuple[str, ...] = Field(default=(), description="True *Pressure conditions")
    control_plane: bool = False


class ClusterGateway(Protocol):
    """Kubernetes operations. Every mutating call supports server-side dry run."""

    async def get_deployment(self, namespace: str, name: str) -> DeploymentState: ...

    async def list_replicasets(
        self, namespace: str, selector: dict[str, str]
    ) -> Sequence[ReplicaSetState]: ...

    async def list_pods(self, namespace: str, selector: dict[str, str]) -> Sequence[PodState]: ...

    async def get_node(self, name: str) -> NodeState: ...

    async def list_nodes(self) -> Sequence[NodeState]: ...

    async def restart_deployment(
        self, namespace: str, name: str, *, at: datetime, dry_run: bool
    ) -> DeploymentState: ...

    async def scale_deployment(
        self, namespace: str, name: str, replicas: int, *, dry_run: bool
    ) -> DeploymentState: ...

    async def replace_pod_template(
        self,
        namespace: str,
        name: str,
        template: dict[str, Any],
        *,
        resource_version: str,
        dry_run: bool,
    ) -> DeploymentState: ...

    async def set_unschedulable(
        self, name: str, unschedulable: bool, *, dry_run: bool
    ) -> NodeState: ...


# ---------------------------------------------------------------- terraform


class CommandResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    args: tuple[str, ...]
    exit_code: int
    stdout_tail: str
    stderr_tail: str
    duration_s: float


class TerraformRunner(Protocol):
    """Runs Terraform against a stack directory under a configured root."""

    async def show_plan(self, stack: str, plan_file: str) -> dict[str, Any]: ...

    async def plan(self, stack: str, out_file: str) -> CommandResult: ...

    async def apply(self, stack: str, plan_file: str) -> CommandResult: ...

    async def check_converged(self, stack: str) -> CommandResult: ...


# ------------------------------------------------------------- repositories


class IncidentRepository(Protocol):
    """``update`` succeeds only if the stored version equals ``expected_version``."""

    async def add(self, incident: Incident) -> None: ...

    async def get(self, incident_id: str) -> Incident | None: ...

    async def find_open(self, fingerprint: str) -> Incident | None: ...

    async def update(self, incident: Incident, *, expected_version: int) -> None: ...

    async def list(
        self, *, status: IncidentStatus | None = None, limit: int = 100, offset: int = 0
    ) -> Sequence[Incident]: ...


class PlanRepository(Protocol):
    async def add(self, plan: RemediationPlan) -> None: ...

    async def get(self, plan_id: str) -> RemediationPlan | None: ...

    async def update(self, plan: RemediationPlan, *, expected_version: int) -> None: ...

    async def list(
        self, *, status: PlanStatus | None = None, limit: int = 100, offset: int = 0
    ) -> Sequence[RemediationPlan]: ...

    async def active_for_target(self, target_ref: str) -> Sequence[RemediationPlan]: ...
