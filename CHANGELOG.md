# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [0.1.0] - 2026-10-14

### Added

- Alert ingestion from Prometheus Alertmanager (webhook v4) and CloudWatch alarms via
  Amazon SNS with SignatureVersion 2 verification, topic allow list and replay window.
- Incident correlation by fingerprint with a database-enforced single open incident.
- Diagnosis playbooks with read-only evidence collection from Kubernetes and an optional,
  guarded, advisory model-written narrative.
- Terraform plan analysis: destructive and stateful changes, disabled safety attributes,
  security-sensitive changes, drift, transitive blast radius and risk score.
- Remediation policy on the agentic-core policy engine, change calendar with freezes, and
  code-enforced invariants (no stateful destroy, approval floor, two-person rule).
- Digest-bound human approvals with separation of duties and plan expiry.
- Remediation executor: Kubernetes restart, scale, rollout undo, cordon and uncordon;
  Terraform apply of re-verified saved plans; post-checks and automatic rollback.
- Dry run by default (server-side `dryRun=All`); live execution only when enabled.
- Agent identity fabric integration (introspection, authorization, own credential) with a
  local policy fallback; MCP tools and A2A agent card with `message/send`.
- Signed audit chain, Prometheus metrics, OpenTelemetry tracing, alert rules, dashboard.
- Helm chart, Kubernetes manifests, Terraform for AWS, Azure and GCP.
- CI: lint, types, SAST, contract drift, unit, security, chaos, performance, e2e and
  PostgreSQL integration tests, Helm and kubeconform, Terraform validate, Trivy, Syft,
  Grype, Semgrep, container smoke test; release with provenance, chart and SBOM.
