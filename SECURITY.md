# Security Policy

## Supported versions

Security fixes are released for the latest minor version.

## Reporting a vulnerability

Do not open a public issue. Use GitHub private vulnerability reporting
(Security tab, "Report a vulnerability"). Include affected version, a
description of the issue, reproduction steps and impact.

Expected handling:

| Stage | Target |
|---|---|
| Acknowledgement | 3 business days |
| Triage and severity (CVSS v4) | 10 business days |
| Fix for critical/high | 30 days from triage |
| Coordinated disclosure | After a fixed release is available |

## Scope

In scope: code in this repository, in particular alert ingestion and SNS
signature verification, caller authorization, the remediation policy and its
invariants, approval handling, plan digest verification, the remediation
executor and rollback, and the Helm chart and Terraform modules.

Security-relevant paths are owned by the code owners listed in `CODEOWNERS`:
`src/self_healing_infrastructure_agents/security/`,
`src/self_healing_infrastructure_agents/governance/`,
`src/self_healing_infrastructure_agents/remediation/`, `policies/` and
`deployments/`.
