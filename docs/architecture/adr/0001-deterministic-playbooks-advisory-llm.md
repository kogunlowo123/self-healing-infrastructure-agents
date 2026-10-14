# ADR-0001: Deterministic playbooks decide; the model only narrates

- Status: Accepted
- Date: 2026-10-14

## Context

A language model could read an alert and propose a fix. Alert text, however,
comes from monitored systems and anything that can write a log line or an
annotation can influence it. A remediation chosen by a model is hard to
test, hard to explain to an auditor, and exposed to prompt injection.

## Decision

- Diagnosis is deterministic: versioned YAML playbooks match alerts, run
  read-only evidence collectors and evaluate hypotheses with agentic-core
  policy conditions. Actions come only from playbook templates; Terraform
  applies cannot be templated at all.
- An optional narrator writes a short incident note through the agentic-core
  `ModelRouter`. Alert text is passed as EXTERNAL trust content, so
  `ContentGuard` scores it for injection, redacts PII and isolates it; the
  output is checked for credentials. The narrative is stored but never read
  by any decision path.
- Missing evidence never produces an action; it lowers to escalation.

## Consequences

- Every remediation can be reproduced from the playbook version and the
  recorded evidence facts.
- New failure modes need a playbook change and review, not a prompt change.
- The service runs fully without any model provider configured.
