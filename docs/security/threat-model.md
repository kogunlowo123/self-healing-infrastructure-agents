# Threat model

## Assets

| Asset | Impact if compromised |
|---|---|
| Ability to change Kubernetes workloads and nodes | Outage, capacity loss, running unreviewed code |
| Ability to apply Terraform | Data loss, security posture changes, cost |
| Remediation policy, change calendar, playbooks | Unsafe actions allowed silently |
| Approval records and plan digests | Changes executed without real human consent |
| Audit chains | Loss of accountability; failed change-management evidence |
| Webhook credential, audit signing key, database URL | Forged incidents, forged evidence, data tampering |

## Trust boundaries

1. Monitoring sources (Alertmanager, SNS) → ingestion endpoints.
2. Operators and agents → REST, MCP and A2A APIs.
3. Service → Kubernetes API server, Terraform CLI and cloud APIs.
4. Service → identity fabric, enterprise IdP JWKS, SNS certificate endpoints.
5. Service → model providers (optional narrator).
6. Service → PostgreSQL, secret store, audit storage.

## STRIDE

| ID | Threat | Category | Control | Test |
|---|---|---|---|---|
| T1 | Forged CloudWatch alarm triggers remediation | Spoofing | SNS SignatureVersion 2 verification, certificate from an `sns.<region>.amazonaws.com` HTTPS URL matching the topic region, topic allow list | `tests/security/test_ingestion_security.py::TestCloudWatchSns::test_signature_from_another_key_rejected`, `test_spoofing_and_replay` |
| T2 | Captured SNS message replayed later | Spoofing | Timestamp replay window | `test_spoofing_and_replay` (timestamp case) |
| T3 | Alarm content altered in transit | Tampering | Signature over the canonical string | `test_tampered_message_rejected` |
| T4 | Subscription confirmation used for SSRF | Tampering | SubscribeURL host and region checks before visiting | `test_subscription_confirmation_visits_aws_only` |
| T5 | Unauthenticated Alertmanager posts | Spoofing | Bearer credential, constant-time compare; endpoint disabled when unconfigured | `TestAlertmanagerWebhook::test_credential_required`, `test_disabled_when_unconfigured` |
| T6 | `alg: none`, expired, foreign-key or wrong-audience tokens | Spoofing | Single verifier per issuer, algorithm allow list, injected clock | `tests/security/test_authorization_and_safety.py::TestAuthentication` |
| T7 | Agent acts beyond its scopes | Elevation | Fabric `/v1/authorize` or local access policy per action | `TestAuthorization::test_agent_needs_matching_scope` |
| T8 | Agent or requester approves its own change | Elevation / repudiation | Approval only with operator OIDC role; requester excluded; distinct approvers | `test_agents_cannot_approve`, `test_requester_cannot_self_approve_and_viewer_cannot_approve`, `tests/unit/test_services.py::TestApprovals` |
| T9 | Long delegation chains launder authority | Elevation | Depth limit; delegated proposals held for approval | `test_delegated_agent_proposals_are_held` |
| T10 | Stateful resource destroyed via Terraform | Tampering / DoS | Code invariant and policy deny; approvals cannot override | `tests/unit/test_governor.py::TestTerraform::test_stateful_destroy_always_denied`, `test_stateful_destroy_cannot_be_approved_into_execution` |
| T11 | Plan file swapped after approval | Tampering | Plan digest bound to approval; re-verified before apply | `tests/unit/test_executor.py::TestTerraform::test_swapped_plan_is_refused`, `tests/unit/test_models.py::TestRemediationPlan::test_digest_is_stable_and_verified_on_load` |
| T12 | Path traversal through stack or plan names | Tampering | Strict patterns; resolved paths must stay under the root | `test_plan_file_traversal_rejected`, `tests/unit/test_terraform_cli.py::test_paths_cannot_escape_root` |
| T13 | Prompt injection in alert text steers remediation | Tampering | Deterministic playbooks; narrator output never used; ContentGuard | `test_prompt_injection_in_alert_cannot_choose_actions`, `tests/unit/test_diagnosis.py::TestNarrator::test_injection_in_alert_text_withholds_narrative` |
| T14 | Remediation makes things worse | DoS | Post-check and automatic rollback; ambiguous failures roll back | `tests/unit/test_executor.py::TestKubernetesActions` |
| T15 | Concurrent writers overwrite each other | Tampering | `resourceVersion` JSON-patch test; compare-and-set plan versions; one active plan per target | `test_rejected_apply_is_plain_failure`, `tests/unit/test_services.py::TestExecute::test_concurrent_execution_is_prevented` |
| T16 | Acting on partial evidence during outages | DoS / tampering | Missing facts deny; collector errors escalate | `tests/chaos/test_dependency_failures.py::test_kubernetes_outage_escalates_instead_of_acting`, `test_governor.py::test_missing_facts_deny` |
| T17 | Audit write fails silently | Repudiation | Audit failure fails the operation | `tests/chaos/test_dependency_failures.py::test_audit_failure_blocks_remediation` |
| T18 | Identity fabric outage opens access | Elevation | Fail closed (503) for agent callers | `test_identity_fabric_outage_fails_closed` |
| T19 | DNS rebinding against `/mcp` | Spoofing | Host and Origin guard from settings | `test_mcp_rejects_foreign_host_and_origin` |
| T20 | Oversized bodies exhaust memory | DoS | 16 MiB request limit, 1 MiB notification limit, plan resource cap | `test_oversized_body_rejected`, `test_malformed_bodies`, `tests/unit/test_terraform_plan.py::TestInvalidDocuments::test_size_limit` |
| T21 | Service secrets leak into Terraform providers | Information disclosure | Allow-listed child environment | `tests/unit/test_terraform_cli.py::test_show_plan_returns_document` |

## MITRE ATT&CK (Enterprise) techniques addressed

| Technique | Relevance | Mitigation |
|---|---|---|
| T1078 Valid Accounts | Stolen operator or agent tokens | Short-lived tokens, scopes, approvals by distinct humans, audit |
| T1565 Data Manipulation | Forged alerts or altered plans | SNS signatures, payload and plan digests |
| T1485 Data Destruction | Terraform deleting databases or buckets | Stateful destroy invariant, protection-disabled deny |
| T1499 Endpoint Denial of Service | Alert storms, oversized plans | Body limits, correlation by fingerprint, HPA |
| T1562 Impair Defenses | Disabling backups or deletion protection via a plan | `protection_disabled` analysis and deny rule |
| T1609 Container Administration Command / T1610 Deploy Container | Misusing the agent to roll out arbitrary images | Rollout undo restores only an earlier owned ReplicaSet template; no create verbs |
| T1098 Account Manipulation | IAM changes through Terraform | Security-sensitive change flagging and approval |

## MITRE ATLAS (narrator)

| Technique | Mitigation |
|---|---|
| AML.T0051 LLM Prompt Injection | Alert text is EXTERNAL trust; injection scoring blocks the request; output unused for decisions |
| AML.T0054 LLM Jailbreak | Same guard; system prompt restricts the task; narrative withheld when blocked |
| AML.T0048 External Harms | The model cannot trigger actions; only deterministic playbooks can |

## OWASP Top 10 for LLM Applications 2025

| Risk | Control |
|---|---|
| LLM01 Prompt Injection | ContentGuard on input; deterministic decisions |
| LLM02 Sensitive Information Disclosure | PII redaction in and out; credential scan blocks output |
| LLM05 Improper Output Handling | Narrative stored as text only, never executed or parsed into actions |
| LLM06 Excessive Agency | Six action types, policy, approvals, dry-run default |
| LLM09 Misinformation | Narrative labelled advisory; evidence facts stored alongside |
| LLM10 Unbounded Consumption | 400 output tokens, one narrative per diagnosis, optional provider |

## OWASP API Security Top 10 2023

| Risk | Control |
|---|---|
| API1 Broken Object Level Authorization | Every object route authorizes the caller per action and resource ID |
| API2 Broken Authentication | JWT verification with JWKS, algorithm allow list, injected clock |
| API3 Broken Object Property Level Authorization | `extra="forbid"` request models; responses are explicit models |
| API4 Unrestricted Resource Consumption | Body limits, pagination limits, plan size caps |
| API5 Broken Function Level Authorization | Approvals restricted to operator role; agents cannot approve |
| API6 Unrestricted Access to Sensitive Business Flows | Approval floor, two-person rule, plan expiry |
| API7 Server Side Request Forgery | SNS URLs restricted to AWS SNS hosts in the topic region |
| API8 Security Misconfiguration | Fail-closed settings (no allow-all), Helm `required` values, nosniff |
| API9 Improper Inventory Management | Published OpenAPI and JSON Schemas with drift check in CI |
| API10 Unsafe Consumption of APIs | Typed parsing of Kubernetes, fabric and Terraform outputs; malformed data is an error |

## Risk register

| Risk | Likelihood | Impact | Owner | Treatment | Residual |
|---|---|---|---|---|---|
| Playbook selects a harmful action | Low | High | Platform SRE | Policy, approvals in production, post-check rollback | Low |
| Approver rubber-stamps | Medium | High | Change management | Dry-run evidence on plans, two-person rule for CRITICAL, audit review | Medium |
| Rollback cannot restore state | Low | High | Platform SRE | `rollback_failed` pages; runbook | Medium |
| Terraform stack volume tampered | Low | High | Platform security | Digest verification, volume write access limited to pipeline | Low |
| Webhook credential leak | Low | Medium | Platform security | Secret store rotation, rejection alert | Low |
| Model provider unavailable | Medium | Low | Platform SRE | Narrative optional; decisions unaffected | Low |
| Policy edit loosens controls | Medium | High | AI governance | Code invariants, CODEOWNERS review, policy digest in audit | Low |
