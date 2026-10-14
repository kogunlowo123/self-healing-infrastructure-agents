# Remediation failure

`HealRollbackFailed` pages when a live remediation failed its post-check
(or failed ambiguously during apply) and the automatic rollback could not be
verified. The target may be in a changed, unverified state.

1. Find the plan: `GET /v1/remediations?status=failed`, newest first. The
   last execution lists every step with its detail and the snapshot taken
   before the change.
2. Kubernetes actions: compare the live object with the snapshot
   (`snapshot.template`, `snapshot.replicas`, node `unschedulable`).
   Restore manually with `kubectl rollout undo`, `kubectl scale` or
   `kubectl uncordon` as appropriate, then check rollout status.
3. Terraform actions: run `terraform plan` in the stack to see the actual
   drift. If a `rollback_stack` exists but its plan was destructive, the
   step detail lists the findings; review it with the stack owner before
   applying anything.
4. The incident is `escalated`; record the manual resolution on the
   incident channel and in the change record.
5. Keep the plan in place: it is the evidence. Do not re-propose the same
   action until the cause is understood.

## Elevated rollbacks

`HealRollbacksElevated`: more than a quarter of live executions rolled back.

1. Group by action and playbook. A single playbook with many rollbacks
   means its hypothesis is wrong for the workloads it matches: narrow its
   match or raise its confidence threshold.
2. Rollouts that do not complete within `HEAL_ROLLOUT_TIMEOUT_SECONDS`
   might be slow rather than broken; compare with deployment
   `progressDeadlineSeconds`.
3. Consider returning the environment to dry run while investigating.
