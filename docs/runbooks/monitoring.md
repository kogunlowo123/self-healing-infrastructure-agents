# Monitoring

Dashboard: `configs/grafana/self-healing-infrastructure-agents.json`.
Alert rules: `configs/prometheus/alerts.yaml`.

| Signal | Healthy | Investigate when |
|---|---|---|
| `1 - heal:request_errors:ratio_5m` | ≥ 99.9% | Burn-rate alert fires |
| `heal_remediations_total{outcome="rollback_failed"}` | 0 | Any increase (pages) |
| `heal_remediations_total{mode="live",outcome="rolled_back"}` | Rare | Above a quarter of live executions |
| `heal_policy_decisions_total{decision="deny"}` | Low | Sudden rise |
| `heal_plans_expired_total` | Rare | Approval backlog |
| `heal_webhook_rejections_total` | 0 | Any sustained rate |
| `heal_diagnoses_total{outcome="escalated"}` | Depends on playbook coverage | Rising for one playbook |

## Latency

`HealIngestionLatencyHigh`: p99 of `/v1/alerts/*` above 2 s.

1. Ingestion includes diagnosis, which reads the Kubernetes API. Check API
   server latency and throttling (HTTP 429 maps to `integration_unavailable`).
2. Check database latency (`/readyz`, RDS Performance Insights).
3. If the narrator is enabled, check model provider latency; disable it by
   unsetting `HEAL_PROVIDERS_FILE` if needed. Decisions do not depend on it.
4. During alert storms, scale replicas; repeats are correlated by
   fingerprint and only update existing incidents.

## Approval backlog

`HealApprovalsBacklog`: plans expiring without a decision.

1. `GET /v1/remediations?status=awaiting_approval` to see what is waiting.
2. Confirm the approver group actually receives the notification channel.
3. If plans expire for low-risk staging changes, review whether the policy
   is stricter than intended; tightening or loosening goes through review.
4. Expired plans are harmless: re-propose after review.
