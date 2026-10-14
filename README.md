# Self-Healing Infrastructure Agents

Agents that turn infrastructure alerts into verified, reversible remediations.
Alerts from Prometheus Alertmanager and CloudWatch (via SNS) are correlated
into incidents and diagnosed with versioned playbooks against read-only
evidence from the cluster. A selected action becomes a remediation plan that
the policy engine allows, holds for human approval, or denies. Terraform
changes are reviewed through analysis of the saved plan (destructive
actions, stateful resources, disabled safety attributes, blast radius).
Execution snapshots the current state, applies the change, runs a
post-check and rolls back automatically when the check fails. Dry run is the
default; nothing destructive runs without a human approval.

```
Telemetry ─▶ Terraform Analysis ─▶ Policy Validation ─▶ Remediation ─▶ Rollback
(Alertmanager,  (plan JSON: deletes,   (ABAC policy, change   (k8s restart/scale/   (snapshot restore,
 CloudWatch)     blast radius, risk)    windows, approvals)    undo/cordon, tf apply) last-known-good plan)
```

Repository: https://github.com/kogunlowo123/self-healing-infrastructure-agents

## Capabilities

| Capability | Implementation |
|---|---|
| Alert ingestion | Alertmanager webhook (payload v4, bearer credential compared in constant time); CloudWatch alarm state changes through SNS with SignatureVersion 2 (SHA256withRSA) verification, topic allow list, certificate host and region checks, replay window |
| Correlation | One open incident per alert fingerprint, enforced by a unique database column; repeats raise occurrence count and severity |
| Diagnosis | Versioned YAML playbooks (`policies/diagnosis-playbooks.yaml`): crash loops, saturation, memory growth, node failure, managed-service capacity. Evidence collectors read Deployments, ReplicaSets, Pods and Nodes; hypotheses are ranked by confidence; missing evidence never yields an action |
| Advisory narrative | Optional model-written incident note through the agentic-core `ModelRouter` (`configs/providers.yaml`) with `ContentGuard` on input and output; it never chooses or parameterises actions |
| Terraform analysis | `terraform show -json` documents: normalised actions, destructive and stateful changes, disabled safety attributes, security-sensitive types, drift, transitive blast radius from configuration references and state dependencies, 0-100 risk score |
| Policy validation | agentic-core `PolicyEngine` over `policies/remediation.yaml`, change calendar (`policies/change-windows.yaml`), plus code invariants: no stateful destroy, approval floor for live production and Terraform changes, two-person rule for CRITICAL risk, deny on missing facts |
| Approvals | Human operators only (enterprise OIDC role `remediation-approver`); approvals are bound to the plan digest; requesters cannot approve their own plans; plans expire |
| Remediation | Kubernetes rolling restart, scale, rollout undo, cordon and uncordon through the API server (server-side `dryRun=All` for dry runs, JSON-patch `test` precondition on `resourceVersion`); Terraform apply of the exact reviewed saved plan, re-verified by digest before apply |
| Rollback | Snapshot restore with its own verification for Kubernetes actions; for Terraform, a fresh plan of the last-known-good stack applied only when non-destructive |
| Agent identity | Inbound agent calls authorized by the agent identity fabric (`/v1/authorize`, `/oauth2/introspect`) or, without a fabric URL, by local JWKS verification and `policies/agent-access.yaml`; the service checks its own fabric credential before every live action |
| MCP and A2A | Eight MCP tools on `/mcp` (official MCP Python SDK, streamable HTTP); A2A agent card and JSON-RPC `message/send` on `/a2a` |
| Audit | Hash-chained, Ed25519-signed agentic-core `AuditLog` for every decision, approval, execution and tool call |
| Observability | Prometheus metrics, OpenTelemetry traces, JSON logs with correlation IDs, SLO and safety alerts, Grafana dashboard |

Shared controls (policy engine, audit chain, model routing, content guard,
logging, telemetry) come from
[agentic-core](https://github.com/kogunlowo123/agentic-core).

## Quick start (local)

Requires Docker. No API keys or cloud credentials are needed; the service
starts in dry-run mode.

```bash
docker compose up --build
curl -s localhost:8080/readyz
curl -s localhost:8080/.well-known/agent-card.json
```

## Development

```bash
uv sync
make check        # ruff, black, mypy --strict, bandit, contracts, tests (coverage >= 90%)
make integration  # PostgreSQL integration tests (needs HEAL_TEST_DATABASE_URL)
make helm         # helm lint with CI values
make terraform    # terraform fmt + validate for aws, azure, gcp
```

Test suites:

| Suite | Content |
|---|---|
| `tests/unit` | Models and state machines, ingestion, Terraform analysis on recorded plans, change calendar, governor, diagnosis, Kubernetes adapter on recorded API wire documents, Terraform CLI runner with a stand-in executable, identity fabric client, executor, services, runtime |
| `tests/security` | Forged and replayed SNS messages, webhook credentials, token attacks, scope and approval bypass, stateful-destroy override, plan path traversal, prompt injection in alerts, MCP host and origin checks |
| `tests/chaos` | Database, Kubernetes API, Terraform, identity fabric and audit failures |
| `tests/performance` | Latency budgets; `locustfile.py` for alert storms against staging |
| `tests/e2e` | Full HTTP lifecycle, MCP and A2A over HTTP, property-based OpenAPI contract test |
| `tests/integration` | Repositories against PostgreSQL |

Fixtures: `tests/fixtures/terraform/terraform-data-*.plan.json` were recorded
with Terraform 1.7.5; the `aws-*` plans keep that recorded structure with AWS
resource types and attributes. Kubernetes fixtures follow the API server's
wire format.

## API

| Endpoint | Caller | Purpose |
|---|---|---|
| `POST /v1/alerts/alertmanager` | Alertmanager | Ingest a webhook notification |
| `POST /v1/alerts/cloudwatch` | Amazon SNS | Ingest a signed CloudWatch alarm; confirm subscriptions |
| `GET /v1/incidents`, `GET /v1/incidents/{id}` | Operators, agents (`incidents:read`) | Incidents with alerts and diagnosis |
| `POST /v1/incidents/{id}/diagnose` | Operators, agents (`alerts:diagnose`) | Re-run diagnosis on fresh evidence |
| `POST /v1/terraform/analyze` | Operators, agents, CI (`terraform:analyze`) | Risk analysis of a plan document |
| `POST /v1/remediations` | Operators, agents (`remediation:propose`) | Propose a remediation; returns the policy outcome |
| `GET /v1/remediations`, `GET /v1/remediations/{id}` | Operators, agents (`remediation:read`) | Plans with approvals and executions |
| `POST /v1/remediations/{id}/decision` | Human approvers (`remediation-approver`) | Approve or reject a plan digest |
| `POST /v1/remediations/{id}/execute` | Operators, agents (`remediation:dry-run` / `remediation:execute`) | Dry run (default) or live execution |
| `POST /mcp/` | MCP clients | MCP streamable HTTP endpoint |
| `GET /.well-known/agent-card.json`, `POST /a2a` | A2A peers | Agent card; JSON-RPC `message/send` |
| `GET /healthz`, `/readyz`, `/metrics` | Platform | Liveness, readiness (database), Prometheus metrics |

Error bodies follow the OAuth style `{"error": ..., "error_description": ...}`.
Full contract: [docs/api/openapi.json](docs/api/openapi.json); JSON Schemas in [schemas/](schemas/).

MCP tools: `list_incidents`, `get_incident`, `diagnose_incident`,
`analyze_terraform_plan`, `propose_remediation`, `list_remediations`,
`dry_run_remediation`, `execute_remediation`.

A2A skills: `get-incident`, `diagnose-incident`, `analyze-terraform-plan`,
`propose-remediation`, `get-remediation`.

## Deployment

| Layer | Location |
|---|---|
| Container image | `Dockerfile` (non-root, includes a checksum-verified Terraform CLI) |
| Helm chart | `deployments/helm/self-healing-infrastructure-agents` |
| Namespace, Alertmanager route and secret sync | `deployments/kubernetes` (least-privilege ClusterRole ships in the chart: `templates/rbac.yaml`) |
| Cloud infrastructure | `deployments/terraform/{aws,azure,gcp}` (AWS is the reference deployment) |

See the [startup runbook](docs/runbooks/startup.md) and
[enabling live execution](docs/runbooks/enabling-live-execution.md).

## Documentation

- [Architecture](docs/architecture/overview.md), [agent specification](docs/architecture/agent-specification.md), [MCP](docs/architecture/mcp.md), [A2A](docs/architecture/a2a.md)
- [ADRs](docs/architecture/adr/)
- [Threat model and risk register](docs/security/threat-model.md)
- [Compliance control mapping](docs/compliance/control-mapping.md)
- Runbooks: [startup](docs/runbooks/startup.md), [monitoring](docs/runbooks/monitoring.md), [incident response](docs/runbooks/incident-response.md), [remediation failure](docs/runbooks/remediation-failure.md), [enabling live execution](docs/runbooks/enabling-live-execution.md), [rollback](docs/runbooks/rollback.md), [disaster recovery](docs/runbooks/disaster-recovery.md)
- [Configuration reference](docs/operations/configuration.md)

## License

Apache-2.0
