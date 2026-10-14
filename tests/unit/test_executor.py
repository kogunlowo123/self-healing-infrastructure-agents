"""Snapshot -> apply -> post-check -> automatic rollback, per action type."""

from __future__ import annotations

from collections import deque
from datetime import timedelta

import pytest

from self_healing_infrastructure_agents.analysis.terraform_plan import analyze_plan
from self_healing_infrastructure_agents.domain.models import (
    ActionKind,
    ActionSpec,
    ExecutionMode,
    ExecutionOutcome,
    RemediationPlan,
    Target,
    TargetKind,
)
from self_healing_infrastructure_agents.remediation.executor import (
    RemediationExecutor,
    previous_template,
)
from tests.conftest import FakeClock, FakeCluster, FakeTerraform, deployment, load, replicaset
from tests.unit.test_models import make_plan

CHECKOUT = Target(
    kind=TargetKind.DEPLOYMENT, name="checkout", namespace="payments", environment="staging"
)
STACK = Target(kind=TargetKind.TERRAFORM_STACK, name="rds/orders", environment="production")


def plan_for(kind: ActionKind, **kw: object) -> RemediationPlan:
    target = {
        ActionKind.CORDON_NODE: Target(kind=TargetKind.NODE, name="node-a"),
        ActionKind.UNCORDON_NODE: Target(kind=TargetKind.NODE, name="node-a"),
        ActionKind.TERRAFORM_APPLY: STACK,
    }.get(kind, CHECKOUT)
    action = ActionSpec.model_validate(
        {"kind": kind, "target": target, "reason": "executor test", **kw}
    )
    analysis = None
    if kind is ActionKind.TERRAFORM_APPLY:
        analysis = analyze_plan(load("terraform/aws-rds-storage-resize.plan.json"))
    return make_plan(action, terraform=analysis)


def executor(
    cluster: FakeCluster, terraform: FakeTerraform, clock: FakeClock
) -> RemediationExecutor:
    return RemediationExecutor(
        cluster, terraform, clock, sleep=clock.sleep, rollout_timeout_s=60, poll_interval_s=5
    )


async def run(
    cluster: FakeCluster,
    terraform: FakeTerraform,
    plan: RemediationPlan,
    mode: ExecutionMode = ExecutionMode.LIVE,
) -> tuple[ExecutionOutcome, list[str]]:
    record = await executor(cluster, terraform, FakeClock()).execute(plan, mode=mode, actor="t")
    return record.outcome, [f"{s.name}:{'ok' if s.ok else 'fail'}" for s in record.steps]


class TestKubernetesActions:
    async def test_restart_success(self, cluster: FakeCluster, terraform: FakeTerraform) -> None:
        outcome, steps = await run(cluster, terraform, plan_for(ActionKind.RESTART_DEPLOYMENT))
        assert outcome is ExecutionOutcome.SUCCEEDED
        assert steps == ["snapshot:ok", "apply:ok", "post-check:ok"]
        assert cluster.deployments[("payments", "checkout")].revision == 8

    async def test_restart_stuck_rolls_back_to_snapshot(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        original = cluster.deployments[("payments", "checkout")].template
        cluster.outcomes = deque(["stuck", "complete"])
        outcome, steps = await run(cluster, terraform, plan_for(ActionKind.RESTART_DEPLOYMENT))
        assert outcome is ExecutionOutcome.ROLLED_BACK
        assert steps[-3:] == ["post-check:fail", "rollback:ok", "rollback-check:ok"]
        assert cluster.deployments[("payments", "checkout")].template == original

    async def test_deadline_exceeded_fails_fast_and_rollback_can_fail(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        cluster.outcomes = deque(["deadline"])
        record = await executor(cluster, terraform, FakeClock()).execute(
            plan_for(ActionKind.RESTART_DEPLOYMENT), mode=ExecutionMode.LIVE, actor="t"
        )
        assert record.outcome is ExecutionOutcome.ROLLBACK_FAILED
        assert "progress deadline exceeded" in record.steps[2].detail
        assert record.snapshot["revision"] == 7

    async def test_scale_and_rollback(self, cluster: FakeCluster, terraform: FakeTerraform) -> None:
        outcome, _ = await run(
            cluster, terraform, plan_for(ActionKind.SCALE_DEPLOYMENT, replicas=6)
        )
        assert outcome is ExecutionOutcome.SUCCEEDED
        assert cluster.deployments[("payments", "checkout")].replicas == 6
        cluster.outcomes = deque(["stuck", "complete"])
        outcome, steps = await run(
            cluster, terraform, plan_for(ActionKind.SCALE_DEPLOYMENT, replicas=9)
        )
        assert outcome is ExecutionOutcome.ROLLED_BACK
        assert cluster.deployments[("payments", "checkout")].replicas == 6
        assert "rollback-check:ok" in steps

    async def test_rollout_undo_uses_previous_revision(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        cluster.replicasets["payments"] = [
            replicaset("checkout", 5, owner="uid-checkout", age=timedelta(days=30)),
            replicaset("checkout", 6, owner="uid-checkout", age=timedelta(days=13)),
            replicaset("checkout", 7, owner="uid-checkout", age=timedelta(minutes=20)),
            replicaset("checkout", 9, owner="someone-else", age=timedelta(minutes=5)),
        ]
        outcome, _ = await run(cluster, terraform, plan_for(ActionKind.ROLLOUT_UNDO))
        assert outcome is ExecutionOutcome.SUCCEEDED
        template = cluster.deployments[("payments", "checkout")].template
        assert template["spec"]["containers"][0]["image"].endswith(":r6")
        assert "pod-template-hash" not in template["metadata"]["labels"]

    async def test_rollout_undo_without_history_fails_safely(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        outcome, steps = await run(cluster, terraform, plan_for(ActionKind.ROLLOUT_UNDO))
        assert outcome is ExecutionOutcome.FAILED
        assert steps == ["snapshot:fail"]
        assert cluster.calls == []

    async def test_cordon_and_ignored_cordon_rolls_back(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        outcome, _ = await run(cluster, terraform, plan_for(ActionKind.CORDON_NODE))
        assert outcome is ExecutionOutcome.SUCCEEDED
        assert cluster.nodes["node-a"].unschedulable
        outcome, _ = await run(cluster, terraform, plan_for(ActionKind.UNCORDON_NODE))
        assert outcome is ExecutionOutcome.SUCCEEDED
        cluster.node_outcomes = deque(["ignored", "complete"])
        outcome, steps = await run(cluster, terraform, plan_for(ActionKind.CORDON_NODE))
        assert outcome is ExecutionOutcome.ROLLED_BACK
        assert steps[-2:] == ["rollback:ok", "rollback-check:ok"]

    async def test_dry_run_changes_nothing(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        before = cluster.deployments[("payments", "checkout")]
        outcome, steps = await run(
            cluster,
            terraform,
            plan_for(ActionKind.SCALE_DEPLOYMENT, replicas=6),
            mode=ExecutionMode.DRY_RUN,
        )
        assert outcome is ExecutionOutcome.SUCCEEDED
        assert steps == ["snapshot:ok", "dry-run:ok"]
        assert cluster.deployments[("payments", "checkout")] == before
        assert cluster.calls == [("scale", "payments", "checkout", 6, True)]

    async def test_cluster_outage_mid_check_rolls_back(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        clock = FakeClock()
        exe = executor(cluster, terraform, clock)
        plan = plan_for(ActionKind.RESTART_DEPLOYMENT)
        original_get = cluster.get_deployment
        calls = {"n": 0}

        async def flaky(namespace: str, name: str):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            if calls["n"] == 3:  # the first post-check poll (after snapshot and apply)
                from self_healing_infrastructure_agents.domain.errors import (
                    IntegrationUnavailableError,
                )

                raise IntegrationUnavailableError("apiserver restarting")
            return await original_get(namespace, name)

        cluster.get_deployment = flaky  # type: ignore[method-assign]
        record = await exe.execute(plan, mode=ExecutionMode.LIVE, actor="t")
        assert record.outcome is ExecutionOutcome.ROLLED_BACK

    async def test_ambiguous_apply_failure_rolls_back(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        cluster.unavailable = {"scale_deployment"}
        record = await executor(cluster, terraform, FakeClock()).execute(
            plan_for(ActionKind.SCALE_DEPLOYMENT, replicas=6), mode=ExecutionMode.LIVE, actor="t"
        )
        # The rollback scale call hits the same outage: humans must look.
        assert record.outcome is ExecutionOutcome.ROLLBACK_FAILED
        assert [s.name for s in record.steps] == ["snapshot", "apply", "rollback"]

    async def test_rejected_apply_is_plain_failure(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        cluster.deployments[("payments", "checkout")] = cluster.deployments[
            ("payments", "checkout")
        ].model_copy(update={"resource_version": "1000"})
        cluster.replicasets["payments"] = [
            replicaset("checkout", 6, owner="uid-checkout", age=timedelta(days=13))
        ]
        plan = plan_for(ActionKind.ROLLOUT_UNDO)
        original_get = cluster.get_deployment
        calls = {"n": 0}

        async def concurrent_writer(namespace: str, name: str):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            state = await original_get(namespace, name)
            if calls["n"] == 2:  # someone else changed it between our read and our patch
                cluster.add(state.model_copy(update={"resource_version": "2000"}))
                return state
            return state

        cluster.get_deployment = concurrent_writer  # type: ignore[method-assign]
        record = await executor(cluster, terraform, FakeClock()).execute(
            plan, mode=ExecutionMode.LIVE, actor="t"
        )
        assert record.outcome is ExecutionOutcome.FAILED
        assert "resourceVersion" in record.steps[-1].detail

    async def test_timeout_without_progress(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        cluster.outcomes = deque(["stuck"])
        record = await executor(cluster, terraform, FakeClock()).execute(
            plan_for(ActionKind.RESTART_DEPLOYMENT), mode=ExecutionMode.LIVE, actor="t"
        )
        assert record.outcome is ExecutionOutcome.ROLLBACK_FAILED
        assert "not complete within" in record.steps[2].detail
        assert record.finished_at - record.started_at >= timedelta(seconds=120)


class TestTerraform:
    async def test_apply_verified_plan(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        outcome, steps = await run(
            cluster, terraform, plan_for(ActionKind.TERRAFORM_APPLY, plan_file="resize.tfplan")
        )
        assert outcome is ExecutionOutcome.SUCCEEDED
        assert steps == ["verify-plan-digest:ok", "apply:ok", "post-check:ok"]
        assert ("apply", "rds/orders", "resize.tfplan") in terraform.calls

    async def test_swapped_plan_is_refused(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        plan = plan_for(ActionKind.TERRAFORM_APPLY, plan_file="resize.tfplan")
        terraform.plans[("rds/orders", "resize.tfplan")] = load(
            "terraform/aws-rds-replace-and-bucket-delete.plan.json"
        )
        record = await executor(cluster, terraform, FakeClock()).execute(
            plan, mode=ExecutionMode.LIVE, actor="t"
        )
        assert record.outcome is ExecutionOutcome.FAILED
        assert "differs from the approved plan" in record.steps[0].detail
        assert not any(c[0] == "apply" for c in terraform.calls)

    async def test_dry_run_verifies_without_applying(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        outcome, steps = await run(
            cluster,
            terraform,
            plan_for(ActionKind.TERRAFORM_APPLY, plan_file="resize.tfplan"),
            mode=ExecutionMode.DRY_RUN,
        )
        assert outcome is ExecutionOutcome.SUCCEEDED
        assert steps == ["verify-plan-digest:ok", "dry-run:ok"]
        assert not any(c[0] == "apply" for c in terraform.calls)

    async def test_unanalysed_plan_refused(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        plan = plan_for(ActionKind.TERRAFORM_APPLY, plan_file="resize.tfplan").model_copy(
            update={"terraform": None}
        )
        outcome, _ = await run(cluster, terraform, plan)
        assert outcome is ExecutionOutcome.FAILED

    async def test_drift_after_apply_without_rollback_stack(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        terraform.converged_exit = deque([2])
        outcome, steps = await run(
            cluster, terraform, plan_for(ActionKind.TERRAFORM_APPLY, plan_file="resize.tfplan")
        )
        assert outcome is ExecutionOutcome.ROLLBACK_FAILED
        assert steps[-1] == "rollback:fail"

    async def test_safe_rollback_from_last_known_good(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        terraform.converged_exit = deque([2, 0])
        terraform.next_plan = load("terraform/aws-rds-storage-resize.plan.json")
        outcome, steps = await run(
            cluster,
            terraform,
            plan_for(
                ActionKind.TERRAFORM_APPLY,
                plan_file="resize.tfplan",
                rollback_stack="rds/orders-lkg",
            ),
        )
        assert outcome is ExecutionOutcome.ROLLED_BACK
        assert steps[-3:] == ["rollback-plan:ok", "rollback:ok", "rollback-check:ok"]
        assert any(
            c[0] == "plan" and c[1] == "rds/orders-lkg" and c[2].startswith("rollback-")
            for c in terraform.calls
        )
        assert any(c[0] == "apply" and c[1] == "rds/orders-lkg" for c in terraform.calls)

    async def test_destructive_rollback_plan_needs_humans(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        terraform.converged_exit = deque([2])
        terraform.next_plan = load("terraform/aws-rds-replace-and-bucket-delete.plan.json")
        outcome, steps = await run(
            cluster,
            terraform,
            plan_for(
                ActionKind.TERRAFORM_APPLY,
                plan_file="resize.tfplan",
                rollback_stack="rds/orders-lkg",
            ),
        )
        assert outcome is ExecutionOutcome.ROLLBACK_FAILED
        assert steps[-1] == "rollback-plan:fail"
        assert not any(c[0] == "apply" and c[1] == "rds/orders-lkg" for c in terraform.calls)

    @pytest.mark.parametrize("failure", ["plan", "apply", "converge"])
    async def test_rollback_failures(
        self, cluster: FakeCluster, terraform: FakeTerraform, failure: str
    ) -> None:
        terraform.next_plan = load("terraform/aws-rds-storage-resize.plan.json")
        terraform.converged_exit = deque([2, 1 if failure == "converge" else 0])
        if failure == "plan":
            terraform.plan_exit = 1
        if failure == "apply":
            terraform.apply_exit = deque([0, 1])
        outcome, _ = await run(
            cluster,
            terraform,
            plan_for(
                ActionKind.TERRAFORM_APPLY,
                plan_file="resize.tfplan",
                rollback_stack="rds/orders-lkg",
            ),
        )
        assert outcome is ExecutionOutcome.ROLLBACK_FAILED

    async def test_failed_apply_attempts_safe_rollback(
        self, cluster: FakeCluster, terraform: FakeTerraform
    ) -> None:
        terraform.apply_exit = deque([1, 0])
        terraform.next_plan = load("terraform/aws-rds-storage-resize.plan.json")
        outcome, steps = await run(
            cluster,
            terraform,
            plan_for(
                ActionKind.TERRAFORM_APPLY,
                plan_file="resize.tfplan",
                rollback_stack="rds/orders-lkg",
            ),
        )
        assert outcome is ExecutionOutcome.ROLLED_BACK
        assert "apply:fail" in steps


def test_previous_template_requires_older_owned_revision() -> None:
    state = deployment(revision=3)
    assert previous_template(state, []) is None
    assert previous_template(state, [{"owner_uid": "other", "revision": 2, "template": {}}]) is None
    no_revision = deployment().model_copy(update={"revision": None})
    assert (
        previous_template(no_revision, [{"owner_uid": None, "revision": 1, "template": {}}]) is None
    )
