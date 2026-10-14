# Enabling live execution

Live execution is enabled per deployment (one deployment per environment or
cluster). Dry run remains the default everywhere else.

## Criteria

- The deployment has run in dry-run mode long enough to cover the incident
  types its playbooks match, and dry-run executions have succeeded at
  admission for those actions.
- Every playbook that can fire in the environment has been reviewed by the
  service owners of the affected workloads.
- Approver group, notification channel and on-call rota exist for the
  environment; `remediation-approver` is assigned only to humans.
- The service's fabric registration carries exactly the action scopes the
  environment should allow.
- Kubernetes RBAC and protected namespaces are reviewed for the cluster.
- For Terraform: stack directories, saved plans and last-known-good stacks
  are produced by the delivery pipeline; the change calendar is correct.
- `HealRollbackFailed` pages the right team.

## Procedure

1. Raise a change record referencing the criteria above.
2. Set `heal.executionMode: live` in the environment's values and upgrade the
   release.
3. Confirm `/readyz` reports `"execution_mode": "live"`.
4. Watch the dashboard for the first executions; review their steps.

## Reverting

Set `heal.executionMode: dry_run` and upgrade. Live requests are then
refused with `live_execution_disabled`; proposals and dry runs continue.
