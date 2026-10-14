# Compliance control mapping

The service is evidence-producing infrastructure: every decision, approval
and change lands in a signed audit chain and in plan records. The tables map
controls to implementation and to evidence in this repository.

## SOC 2 (Trust Services Criteria)

| Control | Implementation | Evidence |
|---|---|---|
| CC6.1 Logical access | OIDC for operators, fabric credentials for agents, scopes per action | `security/callers.py`, `tests/security/test_authorization_and_safety.py` |
| CC6.3 Role-based access, least privilege | Viewer, operator, approver roles; Kubernetes RBAC limited to get/list/patch | `security/operators.py`, `deployments/helm/self-healing-infrastructure-agents/templates/rbac.yaml` |
| CC7.2 Monitoring of anomalies | Prometheus alerts on errors, rollbacks, deny spikes, webhook rejections | `configs/prometheus/alerts.yaml` |
| CC7.3 / CC7.4 Incident evaluation and response | Incidents with diagnosis, escalation, runbooks | `application/incidents.py`, `docs/runbooks/` |
| CC8.1 Change management | Policy-validated proposals, change windows and freezes, approvals bound to plan digest, separation of duties, audit | `governance/`, `application/remediation.py`, `tests/unit/test_services.py::TestApprovals` |

## ISO/IEC 27001:2022 Annex A

| Control | Implementation | Evidence |
|---|---|---|
| 5.15 Access control | Scoped access per action | `security/callers.py` |
| 8.2 Privileged access rights | Live and Terraform changes need human approval; two-person rule | `governance/governor.py` |
| 8.9 Configuration management | Versioned policy, playbooks and calendar; digests recorded with each decision | `policies/`, audit details |
| 8.15 Logging | Signed hash-chained audit events | `tests/unit/test_services.py::TestIncidents::test_rediagnose_and_audit_chain` |
| 8.16 Monitoring activities | Metrics, dashboards, alerts | `configs/` |
| 8.32 Change management | Change windows, freezes, approval workflow, automatic rollback | `policies/change-windows.yaml`, `remediation/executor.py` |

## NIST AI RMF 1.0

| Function | Implementation |
|---|---|
| Govern | Policy ownership, CODEOWNERS, ADRs, code-enforced invariants |
| Map | Agent specification with delegated scope, risk tiers and protected resources |
| Measure | Metrics per playbook and outcome; rollback and deny rates; test suites |
| Manage | Dry-run default, approvals, rollback, escalation, kill switch via execution mode |

## NIST SP 800-53 Rev. 5

| Control | Implementation | Evidence |
|---|---|---|
| AC-3 Access enforcement | Per-action authorization | `tests/security/test_authorization_and_safety.py` |
| AC-6 Least privilege | Six action types, narrow RBAC, protected namespaces | `policies/remediation.yaml` |
| AU-2 Event logging | Every decision, approval, execution and tool call audited | `application/`, `api/mcp_tools.py`, `api/a2a.py` |
| AU-9 Protection of audit information | Signed chain, WORM storage | ADR-0007 |
| AU-10 Non-repudiation | Ed25519 signatures, approver identity and digest per approval | `domain/models.py` |
| CM-3 Configuration change control | Proposal, approval, execution lifecycle | `domain/models.py` state machines |
| CM-4 Impact analyses | Terraform blast radius and risk score; dry runs | `analysis/terraform_plan.py` |
| CM-5 Access restrictions for change | Approver role, separation of duties | `application/remediation.py` |
| CM-6 Configuration settings | Fail-closed settings validation | `config.py`, `tests/unit/test_runtime.py::TestSettings` |
| CP-10 System recovery | Automatic rollback; disaster-recovery runbook | `remediation/executor.py`, `docs/runbooks/disaster-recovery.md` |
| IR-4 Incident handling | Ingestion, diagnosis, remediation, escalation | `application/incidents.py` |
| SI-4 System monitoring | Alert ingestion and service alerts | `ingestion/`, `configs/prometheus/alerts.yaml` |
| SC-8 Transmission confidentiality | TLS to API server, fabric, SNS; Ingress TLS | `integrations/`, Helm chart |
| SA-10 Developer configuration management | CI gates, contract drift, signed release provenance | `.github/workflows/` |

## HIPAA Security Rule (where the platform hosts ePHI workloads)

| Standard | Implementation |
|---|---|
| 164.308(a)(1) Security management process | Risk register, threat model, policy-controlled changes |
| 164.308(a)(4) Information access management | Scoped, role-based access to remediation |
| 164.312(b) Audit controls | Signed audit chains of every change to systems hosting ePHI |
| 164.312(c)(1) Integrity | Stateful destroy prevention, digest-verified changes |

The service does not read application data; alert payloads should not carry
ePHI, and the narrator redacts PII before any model call.

## CIS Kubernetes Benchmark (relevant items)

| Item | Implementation |
|---|---|
| 5.1.1 / 5.1.3 Minimise cluster-admin and wildcard use | ClusterRole lists explicit resources and verbs |
| 5.1.6 Service account tokens only where needed | Token mounted for this workload only |
| 5.2 Pod security | Restricted Pod Security, non-root UID 10001, read-only root filesystem, dropped capabilities |
| 5.3.2 Network policies | Default deny with explicit egress to API server, database, fabric and HTTPS |
