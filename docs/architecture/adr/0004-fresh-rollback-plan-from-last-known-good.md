# ADR-0004: Terraform rollback plans fresh from a last-known-good stack

- Status: Accepted
- Date: 2026-10-14

## Context

The obvious design is to review a rollback plan together with the forward
plan. Terraform rejects a saved plan once the state it was computed against
has changed, and the forward apply changes exactly that state, so a
pre-computed rollback plan is stale by the time it would be needed.

## Decision

- A Terraform remediation may name a `rollback_stack`: a directory holding
  the last-known-good configuration on the same backend.
- If the post-check (`terraform plan -detailed-exitcode`) fails after the
  forward apply, or the apply itself fails, the executor plans that stack
  fresh, analyses the result, and applies it only if it deletes, replaces or
  weakens nothing (no destructive changes, no errored plan, no disabled
  safety attributes). Otherwise it stops with `rollback_failed` and the
  incident is escalated.

## Consequences

- Automatic rollback is limited to non-destructive reversions; anything else
  needs a human, which is the intended trade-off.
- The delivery pipeline must maintain last-known-good stack directories.
