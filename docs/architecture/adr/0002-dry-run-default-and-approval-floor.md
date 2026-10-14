# ADR-0002: Dry run by default and an approval floor in code

- Status: Accepted
- Date: 2026-10-14

## Context

The remediation policy is data and will be edited. A single mistaken edit
must not let the agent delete a database or change production without a
human. Teams also need time to trust the agent before it acts for real.

## Decision

- `HEAL_EXECUTION_MODE` defaults to `dry_run`. Dry runs use the Kubernetes
  API server's `dryRun=All` (admission and validation without persistence)
  and, for Terraform, re-verify the saved plan without applying it. A live
  request while in dry-run mode is refused with `live_execution_disabled`
  rather than silently downgraded.
- On top of the policy, code enforces: no stateful destroys, no errored
  plans, at least one approval for every live Terraform apply and every live
  production change, two distinct approvers for CRITICAL risk, deny when
  required facts are missing.
- Policy is evaluated at proposal and again at execution, with fresh facts
  and the current change window.

## Consequences

- Enabling live execution is an explicit, per-deployment change (see
  `docs/runbooks/enabling-live-execution.md`).
- Policy authors can tighten but not loosen the floor without a code change
  and review.
