"""Remediation and incident services wired through the real container (SQLite, fakes)."""

from __future__ import annotations

from collections import deque
from datetime import timedelta
from pathlib import Path

import pytest
from agentic_core.audit import verify_chain

from self_healing_infrastructure_agents.domain.errors import (
    ApprovalRequiredError,
    ConflictError,
    ForbiddenError,
    InvalidStateError,
    LiveExecutionDisabledError,
    NotFoundError,
    PolicyViolationError,
)
from self_healing_infrastructure_agents.domain.models import (
    ActionKind,
    ActionSpec,
    ApprovalDecision,
    ExecutionMode,
    IncidentStatus,
    PlanStatus,
    Principal,
    PrincipalKind,
    RemediationPlan,
    Target,
    TargetKind,
)
from self_healing_infrastructure_agents.runtime.container import Container
from tests.conftest import (
    FakeClock,
    FakeCluster,
    FakeIdp,
    FakeTerraform,
    make_settings,
    wired,
)
from tests.unit.test_models import make_alert

OPERATOR = Principal(
    subject="user:alice@corp.test",
    kind=PrincipalKind.USER,
    scopes=frozenset({"remediation:execute", "remediation:dry-run", "remediation:propose"}),
)
APPROVER_1 = Principal(subject="user:bob@corp.test", kind=PrincipalKind.USER)
APPROVER_2 = Principal(subject="user:carol@corp.test", kind=PrincipalKind.USER)


def restart(environment: str = "staging", name: str = "checkout") -> ActionSpec:
    return ActionSpec(
        kind=ActionKind.RESTART_DEPLOYMENT,
        target=Target(
            kind=TargetKind.DEPLOYMENT, name=name, namespace="payments", environment=environment
        ),
        reason="service test",
    )


def tf(plan_file: str = "resize.tfplan") -> ActionSpec:
    return ActionSpec(
        kind=ActionKind.TERRAFORM_APPLY,
        target=Target(kind=TargetKind.TERRAFORM_STACK, name="rds/orders", environment="production"),
        plan_file=plan_file,
        reason="grow storage before it runs out",
    )


@pytest.fixture
async def live(
    tmp_path: Path,
    cluster: FakeCluster,
    terraform: FakeTerraform,
    clock: FakeClock,
    operator_idp: FakeIdp,
    agent_idp: FakeIdp,
) -> Container:
    built = await wired(
        make_settings(tmp_path, execution_mode=ExecutionMode.LIVE),
        cluster=cluster,
        terraform=terraform,
        clock=clock,
        operator_idp=operator_idp,
        agent_idp=agent_idp,
    )
    yield built  # type: ignore[misc]
    await built.aclose()


async def approve(c: Container, plan: RemediationPlan, who: Principal) -> RemediationPlan:
    return await c.remediation.decide(
        plan.id,
        approver=who,
        decision=ApprovalDecision.APPROVE,
        plan_digest=plan.digest,
        comment="reviewed evidence",
    )


class TestPropose:
    async def test_statuses_follow_policy(self, container: Container) -> None:
        allowed = await container.remediation.propose(restart(), principal=OPERATOR)
        assert allowed.status is PlanStatus.PROPOSED
        assert allowed.required_approvals == 0
        held = await container.remediation.propose(
            restart("production", "ledger"), principal=OPERATOR
        )
        assert held.status is PlanStatus.AWAITING_APPROVAL
        denied = await container.remediation.propose(tf("replace.tfplan"), principal=OPERATOR)
        assert denied.status is PlanStatus.DENIED
        assert denied.terraform is not None
        assert denied.terraform.stateful_replacements

    async def test_one_active_plan_per_target(self, container: Container, clock: FakeClock) -> None:
        first = await container.remediation.propose(restart(), principal=OPERATOR)
        with pytest.raises(ConflictError, match=first.id):
            await container.remediation.propose(restart(), principal=OPERATOR)
        clock.advance(3601)  # the first plan expires; a new one may be proposed
        second = await container.remediation.propose(restart(), principal=OPERATOR)
        assert (await container.remediation.get(first.id)).status is PlanStatus.EXPIRED
        assert second.status is PlanStatus.PROPOSED

    async def test_unknown_incident(self, container: Container) -> None:
        with pytest.raises(NotFoundError):
            await container.remediation.propose(restart(), principal=OPERATOR, incident_id="nope")

    async def test_unreachable_cluster_denies_scale(
        self, container: Container, cluster: FakeCluster
    ) -> None:
        cluster.unavailable = {"get_deployment"}
        action = ActionSpec(
            kind=ActionKind.SCALE_DEPLOYMENT,
            target=restart().target,
            replicas=6,
            reason="service test",
        )
        plan = await container.remediation.propose(action, principal=OPERATOR)
        assert plan.status is PlanStatus.DENIED
        assert "invariant:facts-unavailable" in plan.policy.matched_rules


class TestApprovals:
    async def test_two_person_rule_and_separation_of_duties(self, container: Container) -> None:
        undo = ActionSpec(
            kind=ActionKind.ROLLOUT_UNDO, target=restart("production").target, reason="bad release"
        )
        plan = await container.remediation.propose(undo, principal=OPERATOR)
        assert plan.required_approvals == 2
        with pytest.raises(ForbiddenError, match="own"):
            await approve(container, plan, OPERATOR)
        with pytest.raises(ConflictError, match="different version"):
            await container.remediation.decide(
                plan.id,
                approver=APPROVER_1,
                decision=ApprovalDecision.APPROVE,
                plan_digest="sha256:" + "0" * 64,
                comment="x",
            )
        once = await approve(container, plan, APPROVER_1)
        assert once.status is PlanStatus.AWAITING_APPROVAL
        with pytest.raises(ConflictError, match="already approved"):
            await approve(container, once, APPROVER_1)
        twice = await approve(container, once, APPROVER_2)
        assert twice.status is PlanStatus.APPROVED
        with pytest.raises(InvalidStateError):
            await approve(container, twice, Principal(subject="user:dave", kind=PrincipalKind.USER))

    async def test_expired_plans_cannot_be_approved(
        self, container: Container, clock: FakeClock
    ) -> None:
        plan = await container.remediation.propose(restart("production"), principal=OPERATOR)
        clock.advance(7200)
        with pytest.raises(InvalidStateError, match="expired"):
            await approve(container, plan, APPROVER_1)

    async def test_rejection(self, container: Container) -> None:
        plan = await container.remediation.propose(restart("production"), principal=OPERATOR)
        rejected = await container.remediation.decide(
            plan.id,
            approver=APPROVER_1,
            decision=ApprovalDecision.REJECT,
            plan_digest=plan.digest,
            comment="not during the sale",
        )
        assert rejected.status is PlanStatus.REJECTED
        with pytest.raises(InvalidStateError):
            await container.remediation.execute(plan.id, principal=OPERATOR, dry_run=True)


class TestExecute:
    async def test_live_disabled_by_default(self, container: Container) -> None:
        plan = await container.remediation.propose(restart(), principal=OPERATOR)
        with pytest.raises(LiveExecutionDisabledError):
            await container.remediation.execute(plan.id, principal=OPERATOR, dry_run=False)
        dry = await container.remediation.execute(plan.id, principal=OPERATOR, dry_run=True)
        assert dry.status is PlanStatus.PROPOSED
        assert dry.executions[-1].mode is ExecutionMode.DRY_RUN

    async def test_live_success_resolves_incident(
        self, live: Container, cluster: FakeCluster
    ) -> None:
        result = await live.incidents.ingest([make_alert(name="Unmatched")], received_by="t")
        incident_id = result.opened[0]
        plan = await live.remediation.propose(
            restart(), principal=OPERATOR, incident_id=incident_id
        )
        done = await live.remediation.execute(plan.id, principal=OPERATOR, dry_run=False)
        assert done.status is PlanStatus.SUCCEEDED
        incident = await live.incidents.get(incident_id)
        assert incident.status is IncidentStatus.RESOLVED
        assert plan.id in incident.plan_ids
        with pytest.raises(InvalidStateError):
            await live.remediation.execute(plan.id, principal=OPERATOR, dry_run=False)

    async def test_failed_remediation_escalates_incident(
        self, live: Container, cluster: FakeCluster
    ) -> None:
        cluster.outcomes = deque(["stuck", "complete"])
        result = await live.incidents.ingest([make_alert(name="Unmatched")], received_by="t")
        plan = await live.remediation.propose(
            restart(), principal=OPERATOR, incident_id=result.opened[0]
        )
        rolled = await live.remediation.execute(plan.id, principal=OPERATOR, dry_run=False)
        assert rolled.status is PlanStatus.ROLLED_BACK
        assert (await live.incidents.get(result.opened[0])).status is IncidentStatus.ESCALATED

    async def test_approvals_required_before_live(self, live: Container) -> None:
        plan = await live.remediation.propose(restart("production"), principal=OPERATOR)
        with pytest.raises(InvalidStateError):
            await live.remediation.execute(plan.id, principal=OPERATOR, dry_run=False)
        approved = await approve(live, plan, APPROVER_1)
        done = await live.remediation.execute(approved.id, principal=OPERATOR, dry_run=False)
        assert done.status is PlanStatus.SUCCEEDED

    async def test_change_window_closing_blocks_execution(
        self,
        tmp_path: Path,
        cluster: FakeCluster,
        terraform: FakeTerraform,
        operator_idp: FakeIdp,
        agent_idp: FakeIdp,
    ) -> None:
        clock = FakeClock(current=FakeClock().current.replace(hour=19, minute=30))  # 15:30 NY
        c = await wired(
            make_settings(tmp_path, execution_mode=ExecutionMode.LIVE, plan_ttl_seconds=7200),
            cluster=cluster,
            terraform=terraform,
            clock=clock,
            operator_idp=operator_idp,
            agent_idp=agent_idp,
        )
        try:
            plan = await c.remediation.propose(tf(), principal=OPERATOR)
            approved = await approve(c, plan, APPROVER_1)
            clock.advance(3600)  # 16:30 New York: window closed
            with pytest.raises(PolicyViolationError, match="outside change window"):
                await c.remediation.execute(approved.id, principal=OPERATOR, dry_run=False)
            assert not any(call[0] == "apply" for call in terraform.calls)
        finally:
            await c.aclose()

    async def test_caller_requiring_approval(self, live: Container) -> None:
        held = OPERATOR.model_copy(update={"requires_approval": True})
        plan = await live.remediation.propose(restart(), principal=OPERATOR)
        with pytest.raises(ApprovalRequiredError):
            await live.remediation.execute(plan.id, principal=held, dry_run=False)

    async def test_dry_run_of_denied_policy(self, container: Container) -> None:
        plan = await container.remediation.propose(restart(), principal=OPERATOR)
        dry_only = Principal(subject="agent", kind=PrincipalKind.AGENT)
        with pytest.raises(PolicyViolationError):
            await container.remediation.execute(plan.id, principal=dry_only, dry_run=True)

    async def test_concurrent_execution_is_prevented(self, live: Container) -> None:
        plan = await live.remediation.propose(restart(), principal=OPERATOR)
        stale = plan
        executing = stale.transition(PlanStatus.EXECUTING, at=stale.updated_at)
        await live.remediation._plans.update(executing, expected_version=stale.version)
        with pytest.raises(ConflictError, match="concurrently"):
            await live.remediation._plans.update(
                stale.transition(PlanStatus.EXECUTING, at=stale.updated_at),
                expected_version=stale.version,
            )

    async def test_expiry_sweep(self, container: Container, clock: FakeClock) -> None:
        await container.remediation.propose(restart(), principal=OPERATOR)
        await container.remediation.propose(restart("production", "ledger"), principal=OPERATOR)
        assert await container.remediation.expire_stale() == 0
        clock.advance(3601)
        assert await container.remediation.expire_stale() == 2
        assert len(await container.remediation.list(status=PlanStatus.EXPIRED)) == 2


class TestIncidents:
    async def test_open_repeat_resolve(self, container: Container) -> None:
        first = await container.incidents.ingest([make_alert(name="Unmatched")], received_by="t")
        assert len(first.opened) == 1
        assert first.plans == ()
        again = await container.incidents.ingest([make_alert(name="Unmatched")], received_by="t")
        assert again.updated == first.opened
        incident = await container.incidents.get(first.opened[0])
        assert incident.occurrences == 2
        assert incident.status is IncidentStatus.ESCALATED  # no playbook matches
        resolved = await container.incidents.ingest(
            [make_alert(name="Unmatched", status="resolved")], received_by="t"
        )
        assert resolved.resolved == first.opened
        orphan = await container.incidents.ingest(
            [make_alert(fingerprint="am:other", status="resolved")], received_by="t"
        )
        assert orphan.resolved == ()
        assert len(await container.incidents.list(status=IncidentStatus.RESOLVED)) == 1

    async def test_triage_proposes_and_dry_runs(
        self, container: Container, cluster: FakeCluster
    ) -> None:
        from tests.unit.test_diagnosis import crashing, healthy

        cluster.pods["payments"] = crashing(1) + healthy(3)
        result = await container.incidents.ingest(
            [make_alert(name="KubePodCrashLooping")], received_by="t"
        )
        assert len(result.plans) == 1
        plan = await container.remediation.get(result.plans[0])
        assert plan.action.kind is ActionKind.RESTART_DEPLOYMENT
        assert plan.status is PlanStatus.PROPOSED
        assert plan.executions[0].mode is ExecutionMode.DRY_RUN
        assert ("restart", "payments", "checkout", True) in cluster.calls

    async def test_triage_live_when_enabled(self, live: Container, cluster: FakeCluster) -> None:
        from tests.unit.test_diagnosis import crashing, healthy

        cluster.pods["payments"] = crashing(1) + healthy(3)
        result = await live.incidents.ingest(
            [make_alert(name="KubePodCrashLooping")], received_by="t"
        )
        plan = await live.remediation.get(result.plans[0])
        assert plan.status is PlanStatus.SUCCEEDED
        assert (await live.incidents.get(result.opened[0])).status is IncidentStatus.RESOLVED

    async def test_conflicting_auto_proposal_is_logged_not_raised(
        self, container: Container, cluster: FakeCluster
    ) -> None:
        from tests.unit.test_diagnosis import crashing, healthy

        cluster.pods["payments"] = crashing(1) + healthy(3)
        await container.remediation.propose(restart(), principal=OPERATOR)
        result = await container.incidents.ingest(
            [make_alert(name="KubePodCrashLooping")], received_by="t"
        )
        assert result.plans == ()

    async def test_auto_execution_refusal_is_contained(
        self, container: Container, cluster: FakeCluster
    ) -> None:
        from tests.unit.test_diagnosis import crashing, healthy

        cluster.pods["payments"] = crashing(1) + healthy(3)
        cluster.unavailable = {"restart_deployment"}
        result = await container.incidents.ingest(
            [make_alert(name="KubePodCrashLooping")], received_by="t"
        )
        plan = await container.remediation.get(result.plans[0])
        assert plan.executions[0].steps[-1].ok is False

    async def test_race_on_open_fingerprint(self, container: Container) -> None:
        from self_healing_infrastructure_agents.domain.models import Incident

        alert = make_alert(name="Unmatched")
        incident = Incident(
            fingerprint=alert.fingerprint,
            title="x",
            severity=alert.severity,
            status=IncidentStatus.OPEN,
            target=alert.target,
            alerts=(alert,),
            opened_at=alert.received_at,
            updated_at=alert.received_at,
        )
        await container.incidents._incidents.add(incident)
        original = container.incidents._incidents.find_open
        calls = {"n": 0}

        async def first_miss(fingerprint: str):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            return None if calls["n"] == 1 else await original(fingerprint)

        container.incidents._incidents.find_open = first_miss  # type: ignore[method-assign]
        result = await container.incidents.ingest([alert], received_by="t")
        assert result.updated == (incident.id,)

    async def test_rediagnose_and_audit_chain(self, container: Container) -> None:
        result = await container.incidents.ingest([make_alert(name="Unmatched")], received_by="t")
        again = await container.incidents.diagnose(result.opened[0], principal=OPERATOR)
        assert again.diagnosis is not None
        with pytest.raises(NotFoundError):
            await container.incidents.get("missing")
        events = [e async for e in container.audit._sink.read()]
        assert {e.action for e in events} >= {"incident.open", "incident.diagnose"}
        key = container.audit._signer.public_key()
        assert verify_chain(events, {container.audit._key_id: key}) == len(events)

    async def test_agent_identity(self, container: Container) -> None:
        assert container.incidents.agent.subject.startswith("spiffe://")
        assert timedelta(seconds=container.settings.plan_ttl_seconds) == timedelta(hours=1)


class TestFabricSelfAuthorization:
    """Before a live action the agent asks the fabric whether its own credential permits it."""

    async def build(
        self,
        tmp_path: Path,
        decision: str,
        cluster: FakeCluster,
        terraform: FakeTerraform,
        clock: FakeClock,
        operator_idp: FakeIdp,
        agent_idp: FakeIdp,
    ) -> Container:
        import httpx

        from tests.unit.test_identity import FakeFabric

        token_file = tmp_path / "workload-token"
        token_file.write_text("projected-service-account-token", encoding="utf-8")
        return await wired(
            make_settings(
                tmp_path,
                execution_mode=ExecutionMode.LIVE,
                fabric_url="https://identity.corp.test",
                agent_issuer=None,
                agent_jwks_url=None,
                workload_token_file=token_file,
            ),
            cluster=cluster,
            terraform=terraform,
            clock=clock,
            operator_idp=operator_idp,
            agent_idp=agent_idp,
            http=httpx.AsyncClient(transport=httpx.MockTransport(FakeFabric(decision=decision))),
        )

    @pytest.mark.parametrize(
        ("decision", "error"),
        [("deny", PolicyViolationError), ("require_approval", ApprovalRequiredError)],
    )
    async def test_fabric_refusals(
        self,
        tmp_path: Path,
        cluster: FakeCluster,
        terraform: FakeTerraform,
        clock: FakeClock,
        operator_idp: FakeIdp,
        agent_idp: FakeIdp,
        decision: str,
        error: type[Exception],
    ) -> None:
        c = await self.build(tmp_path, decision, cluster, terraform, clock, operator_idp, agent_idp)
        try:
            plan = await c.remediation.propose(restart(), principal=OPERATOR)
            with pytest.raises(error):
                await c.remediation.execute(plan.id, principal=OPERATOR, dry_run=False)
            assert cluster.calls == []
        finally:
            await c.aclose()

    async def test_fabric_allows(
        self,
        tmp_path: Path,
        cluster: FakeCluster,
        terraform: FakeTerraform,
        clock: FakeClock,
        operator_idp: FakeIdp,
        agent_idp: FakeIdp,
    ) -> None:
        c = await self.build(tmp_path, "allow", cluster, terraform, clock, operator_idp, agent_idp)
        try:
            plan = await c.remediation.propose(restart(), principal=OPERATOR)
            done = await c.remediation.execute(plan.id, principal=OPERATOR, dry_run=False)
            assert done.status is PlanStatus.SUCCEEDED
        finally:
            await c.aclose()
