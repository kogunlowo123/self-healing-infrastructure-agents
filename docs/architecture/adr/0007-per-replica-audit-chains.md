# ADR-0007: Per-replica signed audit chains

- Status: Accepted
- Date: 2026-10-14

## Context

The agentic-core `AuditLog` is a hash chain: every event commits to its
predecessor and is signed with Ed25519. Several replicas appending to one
chain would need a distributed lock on every decision.

## Decision

- The service runs as a StatefulSet; each pod writes its own chain to
  `/var/lib/self-healing-agents/audit/<pod>.jsonl` on its own volume.
- A log shipper copies chains to WORM storage provisioned by Terraform
  (S3 Object Lock, immutable Blob, retention-locked GCS).
- If an audit write fails, the operation fails: no remediation, approval or
  tool call completes without evidence.

## Consequences

- Each chain verifies independently with `agentic_core.audit.verify_chain`;
  events across replicas are joined by correlation ID and timestamp.
- Audit volumes are part of the backup scope.
