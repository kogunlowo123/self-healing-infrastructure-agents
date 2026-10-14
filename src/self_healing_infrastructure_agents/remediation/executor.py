"""Remediation execution: snapshot -> apply -> post-check -> automatic rollback.

Every action has four parts:

* ``snapshot``  capture the state needed to undo the change;
* ``apply``     make the change (server-side dry run when ``dry_run``);
* ``verify``    the post-check that decides whether the change worked;
* ``rollback``  restore the snapshot, followed by its own verification.

A dry run stops after ``apply``. A live run whose post-check fails is rolled
back automatically, as is one whose apply failed ambiguously (a timeout or
lost response from the API server, any Terraform apply error). If the
rollback cannot be verified either, the outcome is ``rollback_failed`` and
the incident is escalated to a human.

Terraform: the saved plan is re-read with ``terraform show -json`` and its
digest compared with the reviewed and approved digest before anything is
applied, so a plan swapped after approval is refused. The post-check is
``terraform plan -detailed-exitcode`` (exit 0 = converged). Rollback plans
the last-known-good stack fresh (a saved plan would be stale after the
forward apply) and applies it only if that plan is non-destructive and
deletes nothing stateful; otherwise it stops and escalates.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import timedelta
from typing import Any

from self_healing_infrastructure_agents.analysis.terraform_plan import analyze_plan
from self_healing_infrastructure_agents.domain.errors import (
    HealingError,
    IntegrationUnavailableError,
    PlanTamperedError,
)
from self_healing_infrastructure_agents.domain.models import (
    ActionKind,
    ExecutionMode,
    ExecutionOutcome,
    ExecutionRecord,
    RemediationPlan,
    StepResult,
)
from self_healing_infrastructure_agents.domain.ports import (
    Clock,
    ClusterGateway,
    DeploymentState,
    TerraformRunner,
)

Sleep = Callable[[float], Awaitable[None]]
POD_TEMPLATE_HASH = "pod-template-hash"


def _required[T](value: T | None, name: str) -> T:
    if value is None:
        raise HealingError(f"{name} is required for this action")
    return value


def _maybe_applied(plan: RemediationPlan, error: HealingError) -> bool:
    """Whether a failed apply could still have changed something."""
    if plan.action.kind is ActionKind.TERRAFORM_APPLY:
        return True
    return isinstance(error, IntegrationUnavailableError)


class Steps:
    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self.items: list[StepResult] = []

    def add(self, name: str, ok: bool, detail: str = "") -> bool:
        self.items.append(StepResult(name=name, ok=ok, detail=detail[:2000], at=self._clock.now()))
        return ok


def previous_template(
    deployment: DeploymentState, replicasets: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Template of the newest revision older than the current one (kubectl rollout undo)."""
    older = [
        rs
        for rs in replicasets
        if rs["owner_uid"] in (None, deployment.uid)
        and deployment.revision is not None
        and rs["revision"] < deployment.revision
    ]
    if not older:
        return None
    template: dict[str, Any] = dict(max(older, key=lambda rs: rs["revision"])["template"])
    metadata = dict(template.get("metadata") or {})
    labels = {k: v for k, v in (metadata.get("labels") or {}).items() if k != POD_TEMPLATE_HASH}
    metadata["labels"] = labels
    template["metadata"] = metadata
    return template


class RemediationExecutor:
    def __init__(
        self,
        cluster: ClusterGateway,
        terraform: TerraformRunner,
        clock: Clock,
        *,
        sleep: Sleep = asyncio.sleep,
        rollout_timeout_s: float = 600.0,
        poll_interval_s: float = 5.0,
    ) -> None:
        self._cluster = cluster
        self._terraform = terraform
        self._clock = clock
        self._sleep = sleep
        self._timeout = timedelta(seconds=rollout_timeout_s)
        self._interval = poll_interval_s

    async def execute(
        self, plan: RemediationPlan, *, mode: ExecutionMode, actor: str
    ) -> ExecutionRecord:
        started = self._clock.now()
        steps = Steps(self._clock)
        snapshot: dict[str, Any] = {}
        dry_run = mode is ExecutionMode.DRY_RUN
        try:
            snapshot = await self._snapshot(plan, steps)
            await self._apply(plan, snapshot, steps, dry_run=dry_run)
        except HealingError as exc:
            steps.add("apply" if snapshot else "snapshot", False, exc.message)
            outcome = ExecutionOutcome.FAILED
            if snapshot and not dry_run and _maybe_applied(plan, exc):
                # The change may have landed (partial Terraform apply, or a lost API
                # response): restore the snapshot rather than leave it unverified.
                outcome = await self._rollback(plan, snapshot, steps)
            return self._record(
                mode=mode,
                actor=actor,
                started=started,
                outcome=outcome,
                steps=steps,
                snapshot=snapshot,
            )

        if dry_run:
            return self._record(
                mode=mode,
                actor=actor,
                started=started,
                outcome=ExecutionOutcome.SUCCEEDED,
                steps=steps,
                snapshot=snapshot,
            )
        try:
            verified = await self._verify(plan, snapshot, steps)
        except HealingError as exc:
            verified = steps.add("post-check", False, exc.message)
        if verified:
            return self._record(
                mode=mode,
                actor=actor,
                started=started,
                outcome=ExecutionOutcome.SUCCEEDED,
                steps=steps,
                snapshot=snapshot,
            )
        outcome = await self._rollback(plan, snapshot, steps)
        return self._record(
            mode=mode, actor=actor, started=started, outcome=outcome, steps=steps, snapshot=snapshot
        )

    def _record(
        self,
        *,
        mode: ExecutionMode,
        actor: str,
        started: Any,
        outcome: ExecutionOutcome,
        steps: Steps,
        snapshot: dict[str, Any],
    ) -> ExecutionRecord:
        return ExecutionRecord(
            mode=mode,
            actor=actor,
            started_at=started,
            finished_at=self._clock.now(),
            outcome=outcome,
            steps=tuple(steps.items),
            snapshot=snapshot,
        )

    # ------------------------------------------------------------ snapshot

    async def _snapshot(self, plan: RemediationPlan, steps: Steps) -> dict[str, Any]:
        action = plan.action
        target = action.target
        if action.kind is ActionKind.TERRAFORM_APPLY:
            if plan.terraform is None:
                raise HealingError("terraform plan was never analysed")
            document = await self._terraform.show_plan(
                target.name, _required(action.plan_file, "plan_file")
            )
            current = analyze_plan(document)
            if current.plan_digest != plan.terraform.plan_digest:
                raise PlanTamperedError(
                    "saved plan differs from the approved plan "
                    f"({current.plan_digest} != {plan.terraform.plan_digest})"
                )
            steps.add("verify-plan-digest", True, current.plan_digest)
            return {"stack": target.name, "plan_digest": current.plan_digest}
        if action.kind in {ActionKind.CORDON_NODE, ActionKind.UNCORDON_NODE}:
            node = await self._cluster.get_node(target.name)
            steps.add("snapshot", True, f"unschedulable={node.unschedulable}")
            return {"unschedulable": node.unschedulable}
        namespace = _required(target.namespace, "namespace")
        deployment = await self._cluster.get_deployment(namespace, target.name)
        snapshot: dict[str, Any] = {
            "replicas": deployment.replicas,
            "template": deployment.template,
            "revision": deployment.revision,
        }
        if action.kind is ActionKind.ROLLOUT_UNDO:
            replicasets = await self._cluster.list_replicasets(namespace, deployment.selector)
            template = previous_template(
                deployment, [rs.model_dump(mode="json") for rs in replicasets]
            )
            if template is None:
                raise HealingError("no earlier revision to roll back to")
            snapshot["undo_template"] = template
        steps.add(
            "snapshot",
            True,
            f"revision={deployment.revision} replicas={deployment.replicas}",
        )
        return snapshot

    # --------------------------------------------------------------- apply

    async def _apply(
        self, plan: RemediationPlan, snapshot: dict[str, Any], steps: Steps, *, dry_run: bool
    ) -> None:
        action = plan.action
        target = action.target
        label = "dry-run" if dry_run else "apply"
        match action.kind:
            case ActionKind.TERRAFORM_APPLY:
                if dry_run:
                    steps.add(label, True, "plan verified; terraform apply not run in dry run")
                    return
                result = await self._terraform.apply(
                    target.name, _required(action.plan_file, "plan_file")
                )
                if result.exit_code != 0:
                    raise HealingError(
                        f"terraform apply exited {result.exit_code}: "
                        f"{result.stderr_tail[-800:]}"
                    )
                steps.add(label, True, f"terraform apply succeeded in {result.duration_s}s")
            case ActionKind.CORDON_NODE | ActionKind.UNCORDON_NODE:
                desired = action.kind is ActionKind.CORDON_NODE
                node = await self._cluster.set_unschedulable(target.name, desired, dry_run=dry_run)
                steps.add(label, True, f"node unschedulable={node.unschedulable}")
            case ActionKind.RESTART_DEPLOYMENT:
                await self._cluster.restart_deployment(
                    _required(target.namespace, "namespace"),
                    target.name,
                    at=self._clock.now(),
                    dry_run=dry_run,
                )
                steps.add(label, True, "rolling restart requested")
            case ActionKind.SCALE_DEPLOYMENT:
                await self._cluster.scale_deployment(
                    _required(target.namespace, "namespace"),
                    target.name,
                    _required(action.replicas, "replicas"),
                    dry_run=dry_run,
                )
                steps.add(label, True, f"replicas {snapshot['replicas']} -> {action.replicas}")
            case ActionKind.ROLLOUT_UNDO:
                namespace = _required(target.namespace, "namespace")
                current = await self._cluster.get_deployment(namespace, target.name)
                await self._cluster.replace_pod_template(
                    namespace,
                    target.name,
                    snapshot["undo_template"],
                    resource_version=current.resource_version,
                    dry_run=dry_run,
                )
                steps.add(
                    label,
                    True,
                    f"pod template restored from before revision " f"{snapshot['revision']}",
                )

    # -------------------------------------------------------------- verify

    async def _verify(self, plan: RemediationPlan, snapshot: dict[str, Any], steps: Steps) -> bool:
        action = plan.action
        target = action.target
        if action.kind is ActionKind.TERRAFORM_APPLY:
            result = await self._terraform.check_converged(target.name)
            return steps.add(
                "post-check",
                result.exit_code == 0,
                (
                    "infrastructure converged"
                    if result.exit_code == 0
                    else f"terraform plan exit {result.exit_code}: {result.stdout_tail[-500:]}"
                ),
            )
        if action.kind in {ActionKind.CORDON_NODE, ActionKind.UNCORDON_NODE}:
            desired = action.kind is ActionKind.CORDON_NODE
            node = await self._cluster.get_node(target.name)
            return steps.add(
                "post-check", node.unschedulable is desired, f"unschedulable={node.unschedulable}"
            )
        expected = action.replicas if action.kind is ActionKind.SCALE_DEPLOYMENT else None
        ok, detail = await self._wait_for_rollout(target.namespace or "", target.name, expected)
        return steps.add("post-check", ok, detail)

    async def _wait_for_rollout(
        self, namespace: str, name: str, replicas: int | None
    ) -> tuple[bool, str]:
        deadline = self._clock.now() + self._timeout
        last = ""
        while True:
            deployment = await self._cluster.get_deployment(namespace, name)
            last = (
                f"ready {deployment.ready_replicas}/{deployment.replicas}, "
                f"updated {deployment.updated_replicas}, "
                f"observed generation {deployment.observed_generation}/{deployment.generation}"
            )
            if deployment.progress_deadline_exceeded:
                return False, f"progress deadline exceeded ({last})"
            if deployment.rollout_complete and (
                replicas is None or deployment.replicas == replicas
            ):
                return True, f"rollout complete ({last})"
            if self._clock.now() >= deadline:
                return False, f"rollout not complete within {self._timeout} ({last})"
            await self._sleep(self._interval)

    # ------------------------------------------------------------ rollback

    async def _rollback(
        self, plan: RemediationPlan, snapshot: dict[str, Any], steps: Steps
    ) -> ExecutionOutcome:
        try:
            restored = await self._restore(plan, snapshot, steps)
        except HealingError as exc:
            steps.add("rollback", False, exc.message)
            return ExecutionOutcome.ROLLBACK_FAILED
        return ExecutionOutcome.ROLLED_BACK if restored else ExecutionOutcome.ROLLBACK_FAILED

    async def _restore(self, plan: RemediationPlan, snapshot: dict[str, Any], steps: Steps) -> bool:
        action = plan.action
        target = action.target
        if action.kind is ActionKind.TERRAFORM_APPLY:
            return await self._terraform_rollback(plan, steps)
        if action.kind in {ActionKind.CORDON_NODE, ActionKind.UNCORDON_NODE}:
            await self._cluster.set_unschedulable(
                target.name, snapshot["unschedulable"], dry_run=False
            )
            node = await self._cluster.get_node(target.name)
            steps.add("rollback", True, f"unschedulable restored to {snapshot['unschedulable']}")
            return steps.add(
                "rollback-check",
                node.unschedulable is snapshot["unschedulable"],
                f"unschedulable={node.unschedulable}",
            )
        namespace = target.namespace or ""
        if action.kind is ActionKind.SCALE_DEPLOYMENT:
            await self._cluster.scale_deployment(
                namespace, target.name, snapshot["replicas"], dry_run=False
            )
            steps.add("rollback", True, f"replicas restored to {snapshot['replicas']}")
            ok, detail = await self._wait_for_rollout(namespace, target.name, snapshot["replicas"])
            return steps.add("rollback-check", ok, detail)
        current = await self._cluster.get_deployment(namespace, target.name)
        await self._cluster.replace_pod_template(
            namespace,
            target.name,
            snapshot["template"],
            resource_version=current.resource_version,
            dry_run=False,
        )
        steps.add("rollback", True, f"pod template restored to revision {snapshot['revision']}")
        ok, detail = await self._wait_for_rollout(namespace, target.name, None)
        return steps.add("rollback-check", ok, detail)

    async def _terraform_rollback(self, plan: RemediationPlan, steps: Steps) -> bool:
        stack = plan.action.rollback_stack
        if stack is None:
            return steps.add("rollback", False, "no rollback stack configured; escalating")
        out_file = f"rollback-{plan.id[:12]}.tfplan"
        planned = await self._terraform.plan(stack, out_file)
        if planned.exit_code != 0:
            return steps.add("rollback-plan", False, f"terraform plan exited {planned.exit_code}")
        analysis = analyze_plan(await self._terraform.show_plan(stack, out_file))
        if analysis.destructive or analysis.errored or analysis.protection_disabled:
            return steps.add(
                "rollback-plan",
                False,
                "rollback plan is destructive and needs human review: "
                + "; ".join(analysis.findings[:5]),
            )
        steps.add("rollback-plan", True, f"non-destructive rollback plan {analysis.plan_digest}")
        applied = await self._terraform.apply(stack, out_file)
        if applied.exit_code != 0:
            return steps.add("rollback", False, f"terraform apply exited {applied.exit_code}")
        steps.add("rollback", True, "last-known-good configuration applied")
        converged = await self._terraform.check_converged(stack)
        return steps.add(
            "rollback-check", converged.exit_code == 0, f"plan exit {converged.exit_code}"
        )
