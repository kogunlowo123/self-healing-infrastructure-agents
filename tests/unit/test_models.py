"""Domain model invariants: targets, actions, plan and incident state machines."""

from __future__ import annotations

from datetime import timedelta

import pytest
from agentic_core.domain.classification import Decision, RiskLevel
from pydantic import ValidationError

from self_healing_infrastructure_agents.domain.errors import InvalidStateError
from self_healing_infrastructure_agents.domain.models import (
    ActionKind,
    ActionSpec,
    Alert,
    AlertSource,
    AlertStatus,
    Approval,
    ApprovalDecision,
    Diagnosis,
    Evidence,
    Incident,
    IncidentStatus,
    PlanStatus,
    PolicyOutcome,
    RemediationPlan,
    Severity,
    Target,
    TargetKind,
)
from tests.conftest import START


def dep_target(**kw: object) -> Target:
    values: dict[str, object] = {
        "kind": TargetKind.DEPLOYMENT,
        "name": "checkout",
        "namespace": "payments",
        "environment": "staging",
    }
    values.update(kw)
    return Target.model_validate(values)


def make_alert(**kw: object) -> Alert:
    values: dict[str, object] = {
        "source": AlertSource.ALERTMANAGER,
        "fingerprint": "am:1",
        "name": "KubePodCrashLooping",
        "status": AlertStatus.FIRING,
        "severity": Severity.WARNING,
        "starts_at": START,
        "target": dep_target(),
        "payload_digest": "sha256:" + "0" * 64,
        "received_at": START,
    }
    values.update(kw)
    return Alert.model_validate(values)


def make_plan(action: ActionSpec | None = None, **kw: object) -> RemediationPlan:
    values: dict[str, object] = {
        "action": action
        or ActionSpec(kind=ActionKind.RESTART_DEPLOYMENT, target=dep_target(), reason="test"),
        "requested_by": "spiffe://agents.corp.test/agent/sre/triage",
        "created_at": START,
        "updated_at": START,
        "expires_at": START + timedelta(hours=1),
        "status": PlanStatus.AWAITING_APPROVAL,
        "risk": RiskLevel.MODERATE,
        "policy": PolicyOutcome(
            decision=Decision.REQUIRE_APPROVAL,
            matched_rules=("r",),
            policy_name="remediation",
            policy_version="1",
            policy_digest="sha256:x",
            reason="human approval required",
            evaluated_at=START,
        ),
        "required_approvals": 1,
    }
    values.update(kw)
    return RemediationPlan.model_validate(values)


class TestTarget:
    def test_ref_includes_cluster_and_namespace(self) -> None:
        assert dep_target(cluster="eks-1").ref == "eks-1:deployment/payments/checkout"
        node = Target(kind=TargetKind.NODE, name="node-a")
        assert node.ref == "node/node-a"

    @pytest.mark.parametrize(
        "fields",
        [
            {"name": "Bad_Name"},
            {"namespace": None},
            {"namespace": "Bad NS"},
        ],
    )
    def test_invalid_deployment_targets(self, fields: dict[str, object]) -> None:
        with pytest.raises(ValidationError):
            dep_target(**fields)

    def test_nodes_are_cluster_scoped(self) -> None:
        with pytest.raises(ValidationError, match="cluster-scoped"):
            Target(kind=TargetKind.NODE, name="node-a", namespace="x")

    def test_terraform_stacks_allow_paths(self) -> None:
        target = Target(kind=TargetKind.TERRAFORM_STACK, name="rds/orders")
        assert target.ref == "terraform_stack/rds/orders"


class TestActionSpec:
    def test_scale_requires_replicas(self) -> None:
        with pytest.raises(ValidationError, match="replicas"):
            ActionSpec(kind=ActionKind.SCALE_DEPLOYMENT, target=dep_target(), reason="test reason")
        with pytest.raises(ValidationError, match="replicas"):
            ActionSpec(
                kind=ActionKind.RESTART_DEPLOYMENT,
                target=dep_target(),
                replicas=3,
                reason="test reason",
            )

    def test_target_kind_must_match_action(self) -> None:
        with pytest.raises(ValidationError, match="acts on node"):
            ActionSpec(kind=ActionKind.CORDON_NODE, target=dep_target(), reason="test reason")

    def test_terraform_parameters(self) -> None:
        stack = Target(kind=TargetKind.TERRAFORM_STACK, name="rds/orders")
        ok = ActionSpec(
            kind=ActionKind.TERRAFORM_APPLY,
            target=stack,
            plan_file="resize.tfplan",
            rollback_stack="rds/orders-lkg",
            reason="grow storage",
        )
        assert ok.rollback_stack == "rds/orders-lkg"
        with pytest.raises(ValidationError, match="plan_file is required"):
            ActionSpec(kind=ActionKind.TERRAFORM_APPLY, target=stack, reason="test reason")
        with pytest.raises(ValidationError, match="bare file name"):
            ActionSpec(
                kind=ActionKind.TERRAFORM_APPLY,
                target=stack,
                plan_file="../x",
                reason="test reason",
            )
        with pytest.raises(ValidationError, match="invalid Terraform stack"):
            ActionSpec(
                kind=ActionKind.TERRAFORM_APPLY,
                target=Target(kind=TargetKind.TERRAFORM_STACK, name="../etc"),
                plan_file="p.tfplan",
                reason="test reason",
            )
        with pytest.raises(ValidationError, match="must differ"):
            ActionSpec(
                kind=ActionKind.TERRAFORM_APPLY,
                target=stack,
                plan_file="p.tfplan",
                rollback_stack="rds/orders",
                reason="test reason",
            )
        with pytest.raises(ValidationError, match="rollback_stack is only"):
            ActionSpec(
                kind=ActionKind.RESTART_DEPLOYMENT,
                target=dep_target(),
                rollback_stack="x",
                reason="test reason",
            )

    def test_target_kinds_of_actions(self) -> None:
        assert ActionKind.UNCORDON_NODE.target_kind is TargetKind.NODE
        assert ActionKind.TERRAFORM_APPLY.target_kind is TargetKind.TERRAFORM_STACK
        assert ActionKind.ROLLOUT_UNDO.target_kind is TargetKind.DEPLOYMENT


class TestRemediationPlan:
    def test_digest_is_stable_and_verified_on_load(self) -> None:
        plan = make_plan()
        assert plan.digest.startswith("sha256:")
        assert RemediationPlan.model_validate_json(plan.model_dump_json()) == plan
        tampered = plan.model_dump(mode="json")
        tampered["action"]["reason"] = "something else entirely"
        with pytest.raises(ValidationError, match="digest"):
            RemediationPlan.model_validate(tampered)

    def test_transitions(self) -> None:
        plan = make_plan(status=PlanStatus.APPROVED)
        executing = plan.transition(PlanStatus.EXECUTING, at=START)
        assert executing.version == plan.version + 1
        assert executing.transition(PlanStatus.SUCCEEDED, at=START).status is PlanStatus.SUCCEEDED
        with pytest.raises(InvalidStateError):
            plan.transition(PlanStatus.SUCCEEDED, at=START)
        with pytest.raises(InvalidStateError):
            make_plan(status=PlanStatus.DENIED).transition(PlanStatus.EXECUTING, at=START)

    def test_approvals_accumulate_to_required(self) -> None:
        plan = make_plan(required_approvals=2)
        first = plan.with_approval(
            Approval(
                approver="user:a",
                decision=ApprovalDecision.APPROVE,
                comment="ok",
                plan_digest=plan.digest,
                at=START,
            )
        )
        assert first.status is PlanStatus.AWAITING_APPROVAL
        second = first.with_approval(
            Approval(
                approver="user:b",
                decision=ApprovalDecision.APPROVE,
                comment="ok",
                plan_digest=plan.digest,
                at=START,
            )
        )
        assert second.status is PlanStatus.APPROVED
        assert second.approvers == {"user:a", "user:b"}

    def test_rejection_is_final(self) -> None:
        plan = make_plan()
        rejected = plan.with_approval(
            Approval(
                approver="user:a",
                decision=ApprovalDecision.REJECT,
                comment="no",
                plan_digest=plan.digest,
                at=START,
            )
        )
        assert rejected.status is PlanStatus.REJECTED
        assert rejected.approvers == frozenset()


class TestIncident:
    def make(self) -> Incident:
        alert = make_alert()
        return Incident(
            fingerprint=alert.fingerprint,
            title="crash",
            severity=alert.severity,
            status=IncidentStatus.OPEN,
            target=alert.target,
            alerts=(alert,),
            opened_at=START,
            updated_at=START,
        )

    def test_repeat_escalates_severity_and_bounds_history(self) -> None:
        incident = self.make()
        for _ in range(30):
            incident = incident.repeat(make_alert(severity=Severity.CRITICAL))
        assert incident.occurrences == 31
        assert incident.severity is Severity.CRITICAL
        assert len(incident.alerts) == 20
        assert incident.alerts[0].severity is Severity.WARNING  # first notification kept

    def test_lifecycle(self) -> None:
        incident = self.make()
        diagnosis = Diagnosis(
            playbook_id=None,
            playbook_version=None,
            evidence=Evidence(collected_at=START),
            summary="x",
            escalate=True,
        )
        escalated = incident.diagnosed(diagnosis, at=START)
        assert escalated.status is IncidentStatus.ESCALATED
        remediating = escalated.remediating(at=START)
        assert remediating.status is IncidentStatus.REMEDIATING
        resolved = remediating.resolved("fixed", at=START)
        assert not resolved.is_open
        for change in (
            lambda i: i.resolved("again", at=START),
            lambda i: i.remediating(at=START),
            lambda i: i.escalated("x", at=START),
            lambda i: i.diagnosed(diagnosis, at=START),
        ):
            with pytest.raises(InvalidStateError):
                change(resolved)

    def test_severity_rank(self) -> None:
        assert Severity.INFO.rank < Severity.WARNING.rank < Severity.CRITICAL.rank
