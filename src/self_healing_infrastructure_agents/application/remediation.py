"""Remediation lifecycle: propose -> policy -> approve -> execute -> verify -> rollback."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from agentic_core.audit import AuditLog
from agentic_core.domain.classification import Decision
from agentic_core.observability import correlation_id, get_logger

from self_healing_infrastructure_agents.analysis.terraform_plan import analyze_plan
from self_healing_infrastructure_agents.diagnosis.evidence import node_facts
from self_healing_infrastructure_agents.domain.errors import (
    ApprovalRequiredError,
    ConflictError,
    ForbiddenError,
    HealingError,
    InvalidStateError,
    LiveExecutionDisabledError,
    NotFoundError,
    PolicyViolationError,
)
from self_healing_infrastructure_agents.domain.models import (
    TERMINAL_PLAN_STATES,
    ActionKind,
    ActionSpec,
    Approval,
    ApprovalDecision,
    ExecutionMode,
    ExecutionOutcome,
    PlanAnalysis,
    PlanStatus,
    Principal,
    RemediationPlan,
)
from self_healing_infrastructure_agents.domain.ports import (
    Clock,
    ClusterGateway,
    IncidentRepository,
    PlanRepository,
    TerraformRunner,
)
from self_healing_infrastructure_agents.governance.governor import (
    RESOURCE_TYPES,
    RemediationGovernor,
    Verdict,
)
from self_healing_infrastructure_agents.integrations.identity_fabric import (
    FabricCredential,
    IdentityFabricClient,
)
from self_healing_infrastructure_agents.observability.metrics import HealingMetrics
from self_healing_infrastructure_agents.remediation.executor import RemediationExecutor

log = get_logger("self_healing_infrastructure_agents.remediation")

_EXECUTABLE_LIVE = frozenset({PlanStatus.PROPOSED, PlanStatus.APPROVED})
_DRY_RUNNABLE = frozenset({PlanStatus.PROPOSED, PlanStatus.AWAITING_APPROVAL, PlanStatus.APPROVED})
_FINAL_STATUS = {
    ExecutionOutcome.SUCCEEDED: PlanStatus.SUCCEEDED,
    ExecutionOutcome.ROLLED_BACK: PlanStatus.ROLLED_BACK,
    ExecutionOutcome.FAILED: PlanStatus.FAILED,
    ExecutionOutcome.ROLLBACK_FAILED: PlanStatus.FAILED,
}


class RemediationService:
    def __init__(
        self,
        *,
        plans: PlanRepository,
        incidents: IncidentRepository,
        governor: RemediationGovernor,
        executor: RemediationExecutor,
        cluster: ClusterGateway,
        terraform: TerraformRunner,
        audit: AuditLog,
        clock: Clock,
        metrics: HealingMetrics,
        live_execution_enabled: bool,
        plan_ttl: timedelta,
        fabric: tuple[IdentityFabricClient, FabricCredential] | None = None,
    ) -> None:
        self._plans = plans
        self._incidents = incidents
        self._governor = governor
        self._executor = executor
        self._cluster = cluster
        self._terraform = terraform
        self._audit = audit
        self._clock = clock
        self._metrics = metrics
        self._live_enabled = live_execution_enabled
        self._ttl = plan_ttl
        self._fabric = fabric

    @property
    def live_execution_enabled(self) -> bool:
        return self._live_enabled

    # --------------------------------------------------------------- facts

    async def facts_for(self, action: ActionSpec) -> dict[str, Any]:
        """Fresh, read-only facts the policy needs. Unavailable facts are simply absent."""
        target = action.target
        try:
            if action.kind is ActionKind.SCALE_DEPLOYMENT and target.namespace:
                deployment = await self._cluster.get_deployment(target.namespace, target.name)
                wanted = action.replicas or 0
                current = deployment.replicas
                return {
                    "replicas_current": current,
                    "replicas_target": wanted,
                    "scale_factor": round(wanted / current, 4) if current else float(wanted),
                }
            if action.kind in {ActionKind.CORDON_NODE, ActionKind.UNCORDON_NODE}:
                node = await self._cluster.get_node(target.name)
                return node_facts(node, await self._cluster.list_nodes())
            if action.kind is not ActionKind.TERRAFORM_APPLY and target.namespace:
                deployment = await self._cluster.get_deployment(target.namespace, target.name)
                return {"replicas_current": deployment.replicas}
        except HealingError as exc:
            log.warning("facts_unavailable", target=target.ref, error=exc.message)
        return {}

    async def analyze(self, action: ActionSpec) -> PlanAnalysis | None:
        if action.kind is not ActionKind.TERRAFORM_APPLY or action.plan_file is None:
            return None
        analysis = analyze_plan(
            await self._terraform.show_plan(action.target.name, action.plan_file)
        )
        self._metrics.terraform_analyses.labels(analysis.risk.name.lower()).inc()
        return analysis

    def _verdict(
        self,
        principal: Principal,
        action: ActionSpec,
        mode: ExecutionMode,
        facts: dict[str, Any],
        analysis: PlanAnalysis | None,
    ) -> Verdict:
        verdict = self._governor.evaluate(
            principal=principal,
            action=action,
            mode=mode,
            facts=facts,
            at=self._clock.now(),
            analysis=analysis,
        )
        self._metrics.policy_decisions.labels(
            action.kind.value, verdict.outcome.decision.value
        ).inc()
        return verdict

    # ------------------------------------------------------------- propose

    async def propose(
        self, action: ActionSpec, *, principal: Principal, incident_id: str | None = None
    ) -> RemediationPlan:
        if incident_id is not None and await self._incidents.get(incident_id) is None:
            raise NotFoundError(f"incident {incident_id} not found")
        for existing in await self._plans.active_for_target(action.target.ref):
            current = await self._expire_if_due(existing)
            if current.status is not PlanStatus.EXPIRED:
                raise ConflictError(f"plan {current.id} is already active for {action.target.ref}")
        analysis = await self.analyze(action)
        facts = await self.facts_for(action)
        verdict = self._verdict(principal, action, ExecutionMode.LIVE, facts, analysis)
        status = {
            Decision.DENY: PlanStatus.DENIED,
            Decision.REQUIRE_APPROVAL: PlanStatus.AWAITING_APPROVAL,
            Decision.ALLOW: PlanStatus.PROPOSED,
        }[verdict.outcome.decision]
        now = self._clock.now()
        plan = RemediationPlan(
            incident_id=incident_id,
            action=action,
            requested_by=principal.subject,
            created_at=now,
            updated_at=now,
            expires_at=now + self._ttl,
            status=status,
            risk=verdict.risk,
            policy=verdict.outcome,
            required_approvals=verdict.required_approvals,
            terraform=analysis,
        )
        await self._plans.add(plan)
        if incident_id is not None:
            await self._link(incident_id, plan.id)
        await self._audit.record(
            actor=principal.subject,
            action="remediation.propose",
            resource=action.target.ref,
            outcome=verdict.outcome.decision.value,
            correlation_id=correlation_id(),
            details={
                "plan_id": plan.id,
                "plan_digest": plan.digest,
                "action": action.kind.value,
                "risk": verdict.risk.name,
                "required_approvals": verdict.required_approvals,
                "matched_rules": list(verdict.outcome.matched_rules),
                "policy_version": verdict.outcome.policy_version,
                "policy_digest": verdict.outcome.policy_digest,
                "reason": verdict.outcome.reason,
                "terraform_plan_digest": analysis.plan_digest if analysis else None,
            },
        )
        return plan

    async def _link(self, incident_id: str, plan_id: str) -> None:
        incident = await self._incidents.get(incident_id)
        if incident is not None:
            await self._incidents.update(
                incident.with_plan(plan_id, at=self._clock.now()),
                expected_version=incident.version,
            )

    # ------------------------------------------------------------- approve

    async def get(self, plan_id: str) -> RemediationPlan:
        plan = await self._plans.get(plan_id)
        if plan is None:
            raise NotFoundError(f"plan {plan_id} not found")
        return plan

    async def list(
        self, *, status: PlanStatus | None = None, limit: int = 100, offset: int = 0
    ) -> list[RemediationPlan]:
        return list(await self._plans.list(status=status, limit=limit, offset=offset))

    async def _expire_if_due(self, plan: RemediationPlan) -> RemediationPlan:
        if plan.status in TERMINAL_PLAN_STATES or plan.status is PlanStatus.EXECUTING:
            return plan
        if self._clock.now() < plan.expires_at:
            return plan
        expired = plan.transition(PlanStatus.EXPIRED, at=self._clock.now())
        await self._plans.update(expired, expected_version=plan.version)
        self._metrics.plans_expired.inc()
        await self._audit.record(
            actor="system",
            action="remediation.expire",
            resource=plan.action.target.ref,
            outcome="expired",
            correlation_id=correlation_id(),
            details={"plan_id": plan.id},
        )
        return expired

    async def decide(
        self,
        plan_id: str,
        *,
        approver: Principal,
        decision: ApprovalDecision,
        plan_digest: str,
        comment: str,
    ) -> RemediationPlan:
        plan = await self._expire_if_due(await self.get(plan_id))
        if plan.status is not PlanStatus.AWAITING_APPROVAL:
            raise InvalidStateError(f"plan is {plan.status.value}, not awaiting approval")
        if plan_digest != plan.digest:
            raise ConflictError("approval refers to a different version of the plan")
        if approver.subject == plan.requested_by:
            raise ForbiddenError("requesters cannot approve their own remediation")
        if approver.subject in plan.approvers:
            raise ConflictError("this approver has already approved the plan")
        updated = plan.with_approval(
            Approval(
                approver=approver.subject,
                decision=decision,
                comment=comment,
                plan_digest=plan_digest,
                at=self._clock.now(),
            )
        )
        await self._plans.update(updated, expected_version=plan.version)
        self._metrics.approvals.labels(decision.value).inc()
        await self._audit.record(
            actor=approver.subject,
            action=f"remediation.{decision.value}",
            resource=plan.action.target.ref,
            outcome=updated.status.value,
            correlation_id=correlation_id(),
            details={
                "plan_id": plan.id,
                "plan_digest": plan.digest,
                "approvals": len(updated.approvers),
                "required_approvals": plan.required_approvals,
                "comment": comment,
            },
        )
        return updated

    # ------------------------------------------------------------- execute

    async def _self_authorize(self, plan: RemediationPlan) -> None:
        """This agent's own fabric credential must permit the action it is about to take."""
        if self._fabric is None:
            return
        client, credential = self._fabric
        decision = await client.authorize(
            await credential.token(),
            action=plan.action.kind.value,
            resource_type=RESOURCE_TYPES[plan.action.kind],
            resource_id=plan.action.target.ref,
        )
        if decision.decision is Decision.DENY:
            raise PolicyViolationError(
                f"identity fabric denied {plan.action.kind.value} for {credential.agent_id}: "
                f"{decision.reason}",
                rule_ids=decision.matched_rules,
            )
        if decision.decision is Decision.REQUIRE_APPROVAL and not plan.approvers:
            raise ApprovalRequiredError("identity fabric requires a human approval for this action")

    async def execute(
        self, plan_id: str, *, principal: Principal, dry_run: bool
    ) -> RemediationPlan:
        plan = await self._expire_if_due(await self.get(plan_id))
        mode = ExecutionMode.DRY_RUN if dry_run else ExecutionMode.LIVE
        if mode is ExecutionMode.LIVE and not self._live_enabled:
            raise LiveExecutionDisabledError(
                "live execution is disabled (HEAL_EXECUTION_MODE=dry_run); request a dry run"
            )
        allowed = _DRY_RUNNABLE if dry_run else _EXECUTABLE_LIVE
        if plan.status not in allowed:
            raise InvalidStateError(f"plan is {plan.status.value}; cannot run {mode.value}")

        analysis = plan.terraform
        facts = await self.facts_for(plan.action)
        verdict = self._verdict(principal, plan.action, mode, facts, analysis)
        if verdict.outcome.decision is Decision.DENY:
            await self._audit_refusal(plan, principal, mode, verdict.outcome.reason)
            raise PolicyViolationError(
                f"policy denies {mode.value} execution now: {verdict.outcome.reason}",
                rule_ids=verdict.outcome.matched_rules,
            )
        if mode is ExecutionMode.LIVE:
            if principal.requires_approval and not plan.approvers:
                raise ApprovalRequiredError("caller authorization requires a human approval")
            if len(plan.approvers) < verdict.required_approvals:
                await self._audit_refusal(plan, principal, mode, "approvals missing")
                raise ApprovalRequiredError(
                    f"{verdict.required_approvals} approval(s) required, "
                    f"{len(plan.approvers)} recorded"
                )
            await self._self_authorize(plan)
            executing = plan.transition(PlanStatus.EXECUTING, at=self._clock.now())
            await self._plans.update(executing, expected_version=plan.version)
            plan = executing
            await self._mark_incident(plan, remediating=True)

        record = await self._executor.execute(plan, mode=mode, actor=principal.subject)
        updated = plan.with_execution(record)
        if mode is ExecutionMode.LIVE:
            updated = updated.model_copy(update={"status": _FINAL_STATUS[record.outcome]})
        await self._plans.update(updated, expected_version=plan.version)
        elapsed = (record.finished_at - record.started_at).total_seconds()
        kind = plan.action.kind.value
        self._metrics.remediations.labels(kind, mode.value, record.outcome.value).inc()
        self._metrics.remediation_duration.labels(kind, mode.value).observe(max(0.0, elapsed))
        await self._audit.record(
            actor=principal.subject,
            action=f"remediation.execute.{mode.value}",
            resource=plan.action.target.ref,
            outcome=record.outcome.value,
            correlation_id=correlation_id(),
            details={
                "plan_id": plan.id,
                "plan_digest": plan.digest,
                "execution_id": record.id,
                "steps": [s.model_dump(mode="json") for s in record.steps],
                "policy_version": verdict.outcome.policy_version,
                "approvers": sorted(plan.approvers),
            },
        )
        if mode is ExecutionMode.LIVE:
            await self._mark_incident(updated, remediating=False, outcome=record.outcome)
        return updated

    async def _audit_refusal(
        self, plan: RemediationPlan, principal: Principal, mode: ExecutionMode, reason: str
    ) -> None:
        await self._audit.record(
            actor=principal.subject,
            action=f"remediation.execute.{mode.value}",
            resource=plan.action.target.ref,
            outcome="refused",
            correlation_id=correlation_id(),
            details={"plan_id": plan.id, "reason": reason},
        )

    async def _mark_incident(
        self,
        plan: RemediationPlan,
        *,
        remediating: bool,
        outcome: ExecutionOutcome | None = None,
    ) -> None:
        if plan.incident_id is None:
            return
        incident = await self._incidents.get(plan.incident_id)
        if incident is None or not incident.is_open:
            return
        now = self._clock.now()
        if remediating:
            updated = incident.remediating(at=now)
        elif outcome is ExecutionOutcome.SUCCEEDED:
            updated = incident.resolved(f"remediated by plan {plan.id}; post-check passed", at=now)
        else:
            updated = incident.escalated(
                f"remediation plan {plan.id} ended {outcome.value if outcome else 'unknown'}",
                at=now,
            )
        await self._incidents.update(updated, expected_version=incident.version)

    async def expire_stale(self) -> int:
        expired = 0
        for status in (PlanStatus.PROPOSED, PlanStatus.AWAITING_APPROVAL, PlanStatus.APPROVED):
            for plan in await self._plans.list(status=status, limit=500):
                if (await self._expire_if_due(plan)).status is PlanStatus.EXPIRED:
                    expired += 1
        return expired
