"""Remediation policy (policies/remediation.yaml) plus the invariants enforced in code."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from agentic_core.domain.classification import Decision, RiskLevel
from agentic_core.policy import PolicyEngine, PolicySet

from self_healing_infrastructure_agents.analysis.terraform_plan import analyze_plan
from self_healing_infrastructure_agents.domain.models import (
    ActionKind,
    ActionSpec,
    ExecutionMode,
    Principal,
    PrincipalKind,
    Target,
    TargetKind,
)
from self_healing_infrastructure_agents.governance.change_windows import ChangeCalendar
from self_healing_infrastructure_agents.governance.governor import RemediationGovernor, Verdict
from tests.conftest import ROOT, START, load

AGENT = Principal(
    subject="spiffe://agents.corp.test/agent/platform/self-healer",
    kind=PrincipalKind.AGENT,
    scopes=frozenset({"remediation:execute", "remediation:dry-run"}),
)
DRY_ONLY = AGENT.model_copy(update={"scopes": frozenset({"remediation:dry-run"})})
OUTSIDE_WINDOW = datetime(2026, 10, 14, 23, 0, tzinfo=UTC)  # Wednesday 19:00 in New York
FROZEN = datetime(2026, 11, 25, 15, 0, tzinfo=UTC)


@pytest.fixture
def governor() -> RemediationGovernor:
    return RemediationGovernor(
        PolicyEngine(PolicySet.from_file(ROOT / "policies" / "remediation.yaml")),
        ChangeCalendar.from_file(ROOT / "policies" / "change-windows.yaml"),
        protected_namespaces=frozenset({"kube-system"}),
    )


def deployment_action(
    kind: ActionKind = ActionKind.RESTART_DEPLOYMENT,
    *,
    environment: str = "staging",
    namespace: str = "payments",
    replicas: int | None = None,
) -> ActionSpec:
    return ActionSpec(
        kind=kind,
        target=Target(
            kind=TargetKind.DEPLOYMENT,
            name="checkout",
            namespace=namespace,
            environment=environment,
        ),
        replicas=replicas,
        reason="test remediation",
    )


def node_action(
    kind: ActionKind = ActionKind.CORDON_NODE, environment: str = "staging"
) -> ActionSpec:
    return ActionSpec(
        kind=kind,
        target=Target(kind=TargetKind.NODE, name="node-a", environment=environment),
        reason="test remediation",
    )


def tf_action(plan_file: str = "resize.tfplan", environment: str = "production") -> ActionSpec:
    return ActionSpec(
        kind=ActionKind.TERRAFORM_APPLY,
        target=Target(kind=TargetKind.TERRAFORM_STACK, name="rds/orders", environment=environment),
        plan_file=plan_file,
        reason="test remediation",
    )


def evaluate(
    governor: RemediationGovernor,
    action: ActionSpec,
    *,
    facts: dict[str, Any] | None = None,
    principal: Principal = AGENT,
    mode: ExecutionMode = ExecutionMode.LIVE,
    at: datetime = START,
    plan: str | None = None,
) -> Verdict:
    return governor.evaluate(
        principal=principal,
        action=action,
        mode=mode,
        facts=facts or {},
        at=at,
        analysis=analyze_plan(load(f"terraform/{plan}.plan.json")) if plan else None,
    )


class TestKubernetes:
    def test_restart_in_staging_is_allowed(self, governor: RemediationGovernor) -> None:
        verdict = evaluate(governor, deployment_action())
        assert verdict.outcome.decision is Decision.ALLOW
        assert verdict.required_approvals == 0
        assert verdict.risk is RiskLevel.MODERATE
        assert "allow-kubernetes-remediation" in verdict.outcome.matched_rules

    def test_production_live_requires_one_approval(self, governor: RemediationGovernor) -> None:
        verdict = evaluate(governor, deployment_action(environment="production"))
        assert verdict.outcome.decision is Decision.REQUIRE_APPROVAL
        assert verdict.required_approvals == 1
        assert verdict.risk is RiskLevel.HIGH

    def test_rollout_undo_in_production_is_critical_two_person(
        self, governor: RemediationGovernor
    ) -> None:
        verdict = evaluate(governor, deployment_action(ActionKind.ROLLOUT_UNDO, environment="prod"))
        assert verdict.risk is RiskLevel.CRITICAL
        assert verdict.required_approvals == 2

    def test_dry_run_needs_no_approval(self, governor: RemediationGovernor) -> None:
        verdict = evaluate(
            governor,
            deployment_action(environment="production"),
            mode=ExecutionMode.DRY_RUN,
            principal=DRY_ONLY,
        )
        assert verdict.outcome.decision is Decision.ALLOW
        assert verdict.required_approvals == 0

    def test_dry_run_scope_cannot_execute_live(self, governor: RemediationGovernor) -> None:
        assert evaluate(governor, deployment_action(), principal=DRY_ONLY).outcome.decision is (
            Decision.DENY
        )

    def test_protected_namespace_denied(self, governor: RemediationGovernor) -> None:
        verdict = evaluate(governor, deployment_action(namespace="kube-system"))
        assert verdict.outcome.decision is Decision.DENY
        assert "deny-protected-namespaces" in verdict.outcome.matched_rules

    @pytest.mark.parametrize(
        ("current", "target", "decision", "rule"),
        [
            (4, 8, Decision.ALLOW, None),
            (4, 0, Decision.DENY, "deny-scale-to-zero"),
            (40, 60, Decision.DENY, "deny-scale-above-ceiling"),
            (2, 8, Decision.DENY, "deny-scale-step-too-large"),
            (8, 4, Decision.REQUIRE_APPROVAL, "approve-scale-down"),
        ],
    )
    def test_scale_rules(
        self,
        governor: RemediationGovernor,
        current: int,
        target: int,
        decision: Decision,
        rule: str | None,
    ) -> None:
        verdict = evaluate(
            governor,
            deployment_action(ActionKind.SCALE_DEPLOYMENT, replicas=target),
            facts={
                "replicas_current": current,
                "replicas_target": target,
                "scale_factor": target / current,
            },
        )
        assert verdict.outcome.decision is decision
        if rule:
            assert rule in verdict.outcome.matched_rules

    def test_missing_facts_deny(self, governor: RemediationGovernor) -> None:
        verdict = evaluate(governor, deployment_action(ActionKind.SCALE_DEPLOYMENT, replicas=6))
        assert verdict.outcome.decision is Decision.DENY
        assert "invariant:facts-unavailable" in verdict.outcome.matched_rules

    @pytest.mark.parametrize(
        ("facts", "decision"),
        [
            (
                {"ready_nodes_after": 3, "ready_ratio_after": 0.75, "control_plane": False},
                Decision.ALLOW,
            ),
            (
                {"ready_nodes_after": 1, "ready_ratio_after": 0.5, "control_plane": False},
                Decision.DENY,
            ),
            (
                {"ready_nodes_after": 4, "ready_ratio_after": 0.5, "control_plane": False},
                Decision.DENY,
            ),
            (
                {"ready_nodes_after": 9, "ready_ratio_after": 0.9, "control_plane": True},
                Decision.DENY,
            ),
        ],
    )
    def test_cordon_capacity(
        self, governor: RemediationGovernor, facts: dict[str, Any], decision: Decision
    ) -> None:
        assert evaluate(governor, node_action(), facts=facts).outcome.decision is decision

    def test_freeze_blocks_live_rollback_but_not_restart(
        self, governor: RemediationGovernor
    ) -> None:
        undo = evaluate(governor, deployment_action(ActionKind.ROLLOUT_UNDO), at=FROZEN)
        assert undo.outcome.decision is Decision.REQUIRE_APPROVAL  # staging is not frozen then
        prod_undo = evaluate(
            governor,
            deployment_action(ActionKind.ROLLOUT_UNDO, environment="production"),
            at=FROZEN,
        )
        assert prod_undo.outcome.decision is Decision.DENY
        assert "deny-during-freeze" in prod_undo.outcome.matched_rules
        restart = evaluate(governor, deployment_action(environment="production"), at=FROZEN)
        assert restart.outcome.decision is Decision.REQUIRE_APPROVAL

    def test_caller_requiring_approval_raises_floor(self, governor: RemediationGovernor) -> None:
        delegated = AGENT.model_copy(update={"requires_approval": True})
        verdict = evaluate(governor, deployment_action(), principal=delegated)
        assert verdict.outcome.decision is Decision.REQUIRE_APPROVAL
        assert "invariant:approval-floor" in verdict.outcome.matched_rules


class TestTerraform:
    def test_resize_inside_window_requires_approval(self, governor: RemediationGovernor) -> None:
        verdict = evaluate(governor, tf_action(), plan="aws-rds-storage-resize")
        assert verdict.outcome.decision is Decision.REQUIRE_APPROVAL
        assert verdict.outcome.facts["resource"]["stateful_destroys"] == 0
        assert verdict.required_approvals == 1

    def test_outside_window_denied(self, governor: RemediationGovernor) -> None:
        verdict = evaluate(governor, tf_action(), plan="aws-rds-storage-resize", at=OUTSIDE_WINDOW)
        assert verdict.outcome.decision is Decision.DENY
        assert "deny-terraform-outside-change-window" in verdict.outcome.matched_rules
        assert "outside change window" in verdict.outcome.reason

    def test_stateful_destroy_always_denied(self, governor: RemediationGovernor) -> None:
        verdict = evaluate(
            governor, tf_action("replace.tfplan"), plan="aws-rds-replace-and-bucket-delete"
        )
        assert verdict.outcome.decision is Decision.DENY
        assert {"deny-stateful-destroy", "invariant:no-stateful-destroy"} <= set(
            verdict.outcome.matched_rules
        )
        assert verdict.required_approvals == 0

    def test_protection_disabled_denied(self, governor: RemediationGovernor) -> None:
        verdict = evaluate(governor, tf_action("unsafe.tfplan"), plan="aws-rds-protection-disabled")
        assert verdict.outcome.decision is Decision.DENY
        assert "deny-protection-disabled" in verdict.outcome.matched_rules

    def test_errored_plan_denied_by_invariant(self, governor: RemediationGovernor) -> None:
        plan = load("terraform/aws-rds-storage-resize.plan.json")
        plan["errored"] = True
        verdict = governor.evaluate(
            principal=AGENT,
            action=tf_action(),
            mode=ExecutionMode.LIVE,
            facts={},
            at=START,
            analysis=analyze_plan(plan),
        )
        assert verdict.outcome.decision is Decision.DENY
        assert "invariant:applyable-plan" in verdict.outcome.matched_rules

    def test_live_terraform_in_staging_still_needs_approval(
        self, governor: RemediationGovernor
    ) -> None:
        verdict = evaluate(
            governor,
            tf_action(environment="development"),
            plan="aws-rds-storage-resize",
        )
        assert verdict.outcome.decision is Decision.REQUIRE_APPROVAL
        assert verdict.required_approvals == 1

    def test_missing_analysis_denied(self, governor: RemediationGovernor) -> None:
        verdict = evaluate(governor, tf_action())
        assert verdict.outcome.decision is Decision.DENY
        assert "invariant:facts-unavailable" in verdict.outcome.matched_rules
