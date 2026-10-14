# ADR-0005: Kubernetes through a typed REST adapter

- Status: Accepted
- Date: 2026-10-14

## Context

The official Python client is synchronous, untyped for mypy strict, and
generates request shapes indirectly, which makes the exact patches the agent
sends hard to review and to test against recorded API responses.

## Decision

- `integrations/kubernetes.py` calls the API server over HTTPS with httpx:
  apps/v1 Deployments, ReplicaSets and the scale subresource; core/v1 Pods
  and Nodes. Responses are converted into typed port models.
- Mutations use the patch type that matches `kubectl`: strategic merge for
  restart and cordon, merge patch for scale, JSON patch for template
  replacement with a `test` on `metadata.resourceVersion` so a concurrent
  writer makes the patch fail instead of being overwritten.
- Dry runs add `dryRun=All`; every mutation sets `fieldManager`.
- The projected service-account token is re-read for every request because
  the kubelet rotates it; the cluster CA verifies the server.
- Tests run against recorded API server documents in `tests/fixtures/kubernetes`.

## Consequences

- The required RBAC is small and explicit (get/list/patch on four resources).
- Unsupported API errors map to typed domain errors; malformed objects fail
  as integration errors rather than crashes.
