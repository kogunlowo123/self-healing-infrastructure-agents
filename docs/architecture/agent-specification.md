# Agent specification

The self-healing agent is registered in the agent identity fabric like any
other agent. This document states its mandate in the fabric's terms.

## Role and mission

- **Purpose:** restore service health for known failure modes faster than a
  human can, without taking risks a human would not sign off.
- **Business objective:** shorten time to mitigation for repeat incidents
  while keeping change management, audit and segregation of duties intact.
- **Protected resources:** Kubernetes Deployments and Nodes in permitted
  namespaces; Terraform stacks under the configured root; incident and plan
  records; audit evidence.
- **Operating boundaries:** diagnoses from read-only evidence; acts only
  through the six action types below; dry run unless live execution is
  enabled for the deployment; never approves its own plans; never applies a
  Terraform plan that was not reviewed and approved.
- **Delegated responsibility:** what may run is decided by the versioned
  remediation policy and change calendar owned by platform governance; the
  final say on risky changes belongs to human approvers.

## Delegated scope

| Action | Allowed | Disallowed | Risk (base) | Escalation |
|---|---|---|---|---|
| `k8s:restart` | Rolling restart of a Deployment | Protected namespaces (`kube-system`, `kube-public`, `kube-node-lease`) | MODERATE | Approval in production |
| `k8s:scale` | Scale a Deployment, at most tripling, 1 to 50 replicas | Scale to zero, above 50, step above 3x | LOW | Approval for scale-down and in production |
| `k8s:rollout-undo` | Restore the previous ReplicaSet template | During change freezes (live) | HIGH | Always approval when live; two approvers in production (CRITICAL) |
| `k8s:cordon` | Mark a failing node unschedulable | Control-plane nodes; fewer than 2 ready nodes or under two thirds of capacity remaining | MODERATE | Approval in production |
| `k8s:uncordon` | Return a node to scheduling | | LOW | Approval in production |
| `terraform:apply` | Apply a reviewed saved plan inside a change window | Stateful deletes or replacements, disabled safety attributes, errored plans, outside window, during freeze | plan risk, at least MODERATE | Always at least one approval; two for CRITICAL |

Risk is raised one level for production environments.

## Code-enforced invariants

Enforced in `governance/governor.py` regardless of the policy file:

- Terraform plans that delete or replace a stateful resource are denied.
- Errored or non-applyable Terraform plans are denied.
- Live Terraform applies always need at least one human approval.
- Live actions in production always need at least one human approval.
- CRITICAL-risk actions need two distinct approvers (two-person rule).
- If a fact the policy relies on could not be collected, the action is denied.

Enforced elsewhere: approvals bind to the plan digest; the requester cannot
approve; plans expire (`HEAL_PLAN_TTL_SECONDS`); the policy is re-evaluated
at execution time; the saved Terraform plan is re-verified by digest before
apply; the agent's own fabric credential must permit the action.

## Objectives

| Type | Definition | Target |
|---|---|---|
| SLO availability | Non-5xx share of API and webhook requests | 99.9% over 30 days |
| SLO latency | p99 alert ingestion (`/v1/alerts/*`) | < 2 s |
| SLO latency | p99 Terraform plan analysis | < 1 s |
| SLO safety | Remediations ending `rollback_failed` that did not page | 0 |
| SLI | `heal:request_errors:ratio_5m`, `heal_http_request_duration_seconds`, `heal_remediations_total` | Prometheus |
| KPI | Share of incidents with a selected action that ended `succeeded` | Tracked per playbook |
| KPI | Share of live remediations rolled back | Alert above 25% per hour |
| KPI | Plans expiring without a decision | Alert above 3 per 2 hours |
| Completion | An execution is complete when its outcome and every step are in the plan record and the signed audit chain | Enforced: audit failure fails the operation |

## Permissions

| Mechanism | Use |
|---|---|
| RBAC (operators) | Enterprise IdP roles: `remediation-viewer` (incidents:read, remediation:read), `remediation-operator` (adds alerts:diagnose, terraform:analyze, remediation:propose, remediation:dry-run, remediation:execute), `remediation-approver` (remediation:approve) |
| ABAC | `policies/remediation.yaml` over subject (kind, roles, scopes), action, resource facts (environment, namespace, replica counts, node capacity, plan analysis), environment (mode, change window, freeze) and risk |
| Agent identity | SPIFFE ID (`HEAL_AGENT_ID`) registered in the identity fabric; agent callers present fabric-issued credentials |
| OAuth 2.0 / OIDC | Operators: OIDC JWTs verified against the IdP JWKS. Agents: RFC 7662 introspection and fabric `/v1/authorize`; this service obtains its own credential with the RFC 7523 jwt-bearer grant |
| Workload identity | Projected service-account token for the fabric grant and the Kubernetes API; IRSA / Azure Workload Identity / GKE Workload Identity for Terraform and audit storage |
| Kubernetes RBAC | `get`, `list` on deployments, replicasets, pods, nodes; `patch` on deployments, deployments/scale, nodes. No create, delete or secrets access |

## Inputs and outputs

Every request and response is a Pydantic model; JSON Schemas are published
in `schemas/`:

| Schema | Direction |
|---|---|
| `alertmanager-webhook.request` | Alertmanager input |
| `sns-envelope.request`, `cloudwatch-alarm.message` | SNS input |
| `ingest-result.response` | Ingestion output |
| `action-spec`, `propose-remediation.request` | Proposal input |
| `approval.request`, `execute.request` | Decision and execution input |
| `analyze-plan.request`, `plan-analysis.response` | Terraform analysis |
| `diagnosis`, `incident.response`, `remediation-plan.response` | Outputs |

Validation: inputs reject unknown fields; Kubernetes names, stack paths and
plan file names are validated against strict patterns; action parameters
must match the action kind; plan documents must be format 1.x and are
capped in size and resource count.

Provenance: every alert stores `payload_digest` (SHA-256 of the raw
notification); every Terraform analysis stores `plan_digest` over the
canonical plan JSON; every plan stores `digest` over the action and plan
digest, which approvals reference and which is re-checked when the plan is
loaded from storage.

Audit metadata: actor, action, resource, outcome, correlation ID, policy
name, version and digest, matched rules, plan and execution IDs, approvers,
execution steps. Tokens and credentials are never written.
