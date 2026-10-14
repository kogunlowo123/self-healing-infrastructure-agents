"""Incident handling: ingest -> correlate -> diagnose -> propose -> (dry-)run.

Repeated notifications with the same fingerprint update the open incident
instead of opening a new one. A new incident is diagnosed immediately. When
the diagnosis selects an action, this service (acting as the self-healing
agent) proposes it; the remediation policy decides whether it needs human
approval. Plans the policy allows outright are executed automatically in
the configured mode, which is a server-side dry run unless live execution
has been enabled explicitly; plans waiting for approval get a dry run too.
"""

from __future__ import annotations

from collections.abc import Sequence

from agentic_core.audit import AuditLog
from agentic_core.observability import correlation_id, get_logger
from pydantic import BaseModel, ConfigDict

from self_healing_infrastructure_agents.application.remediation import RemediationService
from self_healing_infrastructure_agents.diagnosis.engine import DiagnosisEngine
from self_healing_infrastructure_agents.domain.errors import (
    ConflictError,
    HealingError,
    NotFoundError,
)
from self_healing_infrastructure_agents.domain.models import (
    Alert,
    AlertStatus,
    Incident,
    IncidentStatus,
    PlanStatus,
    Principal,
)
from self_healing_infrastructure_agents.domain.ports import Clock, IncidentRepository
from self_healing_infrastructure_agents.observability.metrics import HealingMetrics

log = get_logger("self_healing_infrastructure_agents.incidents")

_AUTO_RUNNABLE = frozenset({PlanStatus.PROPOSED, PlanStatus.AWAITING_APPROVAL})


class IngestResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    accepted: int
    opened: tuple[str, ...]
    updated: tuple[str, ...]
    resolved: tuple[str, ...]
    plans: tuple[str, ...]


class IncidentService:
    def __init__(
        self,
        *,
        incidents: IncidentRepository,
        engine: DiagnosisEngine,
        remediation: RemediationService,
        audit: AuditLog,
        clock: Clock,
        metrics: HealingMetrics,
        agent: Principal,
        auto_propose: bool,
        auto_execute: bool,
    ) -> None:
        self._incidents = incidents
        self._engine = engine
        self._remediation = remediation
        self._audit = audit
        self._clock = clock
        self._metrics = metrics
        self._agent = agent
        self._auto_propose = auto_propose
        self._auto_execute = auto_execute

    @property
    def agent(self) -> Principal:
        return self._agent

    async def get(self, incident_id: str) -> Incident:
        incident = await self._incidents.get(incident_id)
        if incident is None:
            raise NotFoundError(f"incident {incident_id} not found")
        return incident

    async def list(
        self, *, status: IncidentStatus | None = None, limit: int = 100, offset: int = 0
    ) -> list[Incident]:
        return list(await self._incidents.list(status=status, limit=limit, offset=offset))

    async def ingest(self, alerts: Sequence[Alert], *, received_by: str) -> IngestResult:
        opened: list[str] = []
        updated: list[str] = []
        resolved: list[str] = []
        plans: list[str] = []
        for alert in alerts:
            self._metrics.alerts.labels(alert.source.value, alert.status.value).inc()
            if alert.status is AlertStatus.RESOLVED:
                incident = await self._resolve(alert, received_by)
                if incident is not None:
                    resolved.append(incident.id)
                continue
            existing = await self._incidents.find_open(alert.fingerprint)
            if existing is not None:
                await self._repeat(existing, alert)
                updated.append(existing.id)
                continue
            try:
                incident = await self._open(alert, received_by)
            except ConflictError:
                # Another replica opened it between our lookup and insert.
                raced = await self._incidents.find_open(alert.fingerprint)
                if raced is None:
                    raise
                await self._repeat(raced, alert)
                updated.append(raced.id)
                continue
            opened.append(incident.id)
            plan_id = await self._triage(incident)
            if plan_id:
                plans.append(plan_id)
        return IngestResult(
            accepted=len(alerts),
            opened=tuple(opened),
            updated=tuple(updated),
            resolved=tuple(resolved),
            plans=tuple(plans),
        )

    async def _repeat(self, incident: Incident, alert: Alert) -> None:
        await self._incidents.update(incident.repeat(alert), expected_version=incident.version)

    async def _open(self, alert: Alert, received_by: str) -> Incident:
        now = self._clock.now()
        incident = Incident(
            fingerprint=alert.fingerprint,
            title=alert.summary or alert.name,
            severity=alert.severity,
            status=IncidentStatus.OPEN,
            target=alert.target,
            alerts=(alert,),
            opened_at=now,
            updated_at=now,
        )
        await self._incidents.add(incident)
        self._metrics.incidents_opened.labels(alert.severity.value).inc()
        await self._audit.record(
            actor=received_by,
            action="incident.open",
            resource=alert.target.ref if alert.target else alert.fingerprint,
            outcome=IncidentStatus.OPEN.value,
            correlation_id=correlation_id(),
            details={
                "incident_id": incident.id,
                "alert": alert.name,
                "source": alert.source.value,
                "severity": alert.severity.value,
                "payload_digest": alert.payload_digest,
            },
        )
        return incident

    async def _resolve(self, alert: Alert, received_by: str) -> Incident | None:
        incident = await self._incidents.find_open(alert.fingerprint)
        if incident is None:
            return None
        closed = incident.resolved(
            f"{alert.source.value} reported the alert resolved", at=self._clock.now()
        )
        await self._incidents.update(closed, expected_version=incident.version)
        await self._audit.record(
            actor=received_by,
            action="incident.resolve",
            resource=incident.target.ref if incident.target else incident.fingerprint,
            outcome=IncidentStatus.RESOLVED.value,
            correlation_id=correlation_id(),
            details={"incident_id": incident.id, "payload_digest": alert.payload_digest},
        )
        return closed

    async def diagnose(self, incident_id: str, *, principal: Principal) -> Incident:
        incident = await self.get(incident_id)
        diagnosed = await self._diagnose(incident, actor=principal.subject)
        return diagnosed

    async def _diagnose(self, incident: Incident, *, actor: str) -> Incident:
        diagnosis = await self._engine.diagnose(incident)
        diagnosed = incident.diagnosed(diagnosis, at=self._clock.now())
        await self._incidents.update(diagnosed, expected_version=incident.version)
        self._metrics.diagnoses.labels(
            diagnosis.playbook_id or "none", "escalated" if diagnosis.escalate else "selected"
        ).inc()
        await self._audit.record(
            actor=actor,
            action="incident.diagnose",
            resource=incident.target.ref if incident.target else incident.fingerprint,
            outcome="escalated" if diagnosis.escalate else "action_selected",
            correlation_id=correlation_id(),
            details={
                "incident_id": incident.id,
                "playbook": diagnosis.playbook_id,
                "playbook_version": diagnosis.playbook_version,
                "selected": diagnosis.selected.id if diagnosis.selected else None,
                "confidence": diagnosis.selected.confidence if diagnosis.selected else None,
                "evidence_errors": list(diagnosis.evidence.errors),
                "narrative": diagnosis.narrative is not None,
            },
        )
        return diagnosed

    async def _triage(self, incident: Incident) -> str | None:
        diagnosed = await self._diagnose(incident, actor=self._agent.subject)
        diagnosis = diagnosed.diagnosis
        if (
            not self._auto_propose
            or diagnosis is None
            or diagnosis.selected is None
            or diagnosis.selected.action is None
        ):
            return None
        try:
            plan = await self._remediation.propose(
                diagnosis.selected.action, principal=self._agent, incident_id=incident.id
            )
        except HealingError as exc:
            log.warning("auto_propose_failed", incident=incident.id, error=exc.message)
            return None
        if self._auto_execute and plan.status in _AUTO_RUNNABLE:
            # Allowed plans run live only when live execution is enabled; everything else,
            # including plans waiting for approval, gets a server-side dry run so approvers
            # see admission evidence before deciding.
            live = plan.status is PlanStatus.PROPOSED and self._remediation.live_execution_enabled
            try:
                await self._remediation.execute(plan.id, principal=self._agent, dry_run=not live)
            except HealingError as exc:
                log.warning("auto_execute_failed", plan=plan.id, error=exc.message)
        return plan.id
