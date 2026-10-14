# ADR-0003: Approvals bind to a plan digest, re-verified at apply

- Status: Accepted
- Date: 2026-10-14

## Context

An approver reviews a specific change. If the plan file on disk or the
stored plan record changes between review and execution, the approval no
longer means anything (time-of-check to time-of-use).

## Decision

- Each Terraform analysis records `plan_digest`: SHA-256 over the canonical
  JSON of `terraform show -json`.
- Each remediation plan records `digest` over its ID, its action and the
  Terraform plan digest. Approval requests must carry that digest; a
  mismatch is refused. Loading a plan from storage recomputes the digest and
  rejects a record whose content no longer matches.
- Immediately before `terraform apply`, the executor runs
  `terraform show -json` on the saved plan again and refuses to apply if the
  digest differs from the approved one. Terraform applies the saved plan
  file, never a fresh plan.

## Consequences

- A swapped or edited plan file fails closed with no change made.
- Re-planning after review means a new proposal and new approvals.
