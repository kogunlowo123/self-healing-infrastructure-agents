# Incident response for the service itself

## Immediate containment

To stop all live changes at once, set `heal.executionMode=dry_run` and
upgrade the release (or set `HEAL_EXECUTION_MODE=dry_run`). Plans stay
recorded; nothing further is applied. Executions already running finish
their post-check and rollback.

## Elevated 5xx

`HealErrorBudgetBurnFast`.

1. `kubectl logs` for `error` events; correlate with `X-Correlation-ID`.
2. `/readyz` 503 means the database is unreachable: check credentials sync
   (External Secrets status) and the database instance.
3. `integration_unavailable` errors point to the Kubernetes API, Terraform
   or the identity fabric; the service fails closed by design.
4. If a release caused it, follow [rollback.md](rollback.md).

## Deny spike

`HealPolicyDenySpike`.

1. Group denials by matched rule: plan records carry
   `policy.matched_rules` and the reason.
2. `invariant:facts-unavailable` means evidence could not be read
   (Kubernetes API access or RBAC changed).
3. `deny-terraform-outside-change-window` or `deny-during-freeze` are
   expected during freezes.
4. A misbehaving caller repeatedly proposing denied actions: check its
   identity in the audit chain and suspend it in the identity fabric.

## Webhook rejections

`HealWebhookRejections`, label `reason`:

| Reason | Meaning | Action |
|---|---|---|
| `missing_token`, `bad_token` | Alertmanager credential mismatch | Check secret rotation on both sides; sustained bad tokens from an unknown source are an attack signal |
| `invalid_payload` | Not an Alertmanager v4 payload | Check Alertmanager version and receiver config |
| `invalid_envelope` | Not an SNS message | Check the subscription target |
| `bad_signature` | SNS verification failed | Confirm `SignatureVersion=2` and the topic ARN allow list; otherwise treat as forgery and block the source at the ingress |

## Replicas down

`HealNotReady`.

1. `kubectl describe pod` for scheduling, probe or image pull failures.
2. Audit volumes: a full volume blocks the pod's audit writes and therefore
   its operations; expand the PVC or rotate shipped chains.
3. Pods refuse to start on invalid configuration (settings validation);
   read the first log lines.

## Suspected compromise

1. Switch to dry run (above).
2. Revoke the service's agent identity in the fabric and rotate the
   webhook credential and audit key.
3. Verify audit chains with `agentic_core.audit.verify_chain` and compare
   executed plans with approvals.
