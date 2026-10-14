# Configuration reference

All settings are read from `HEAL_*` environment variables
(`src/self_healing_infrastructure_agents/config.py`). Settings without a
default are required; the service refuses to start without them.

## Core

| Variable | Default | Meaning |
|---|---|---|
| `HEAL_ENVIRONMENT` | `production` | Deployment environment name; `production` forbids ephemeral keys |
| `HEAL_PUBLIC_URL` | required | External URL; used in the A2A agent card and as the allowed MCP host/origin |
| `HEAL_DATABASE_URL` | required | SQLAlchemy async URL (`postgresql+asyncpg://...`) |
| `HEAL_DEFAULT_ALERT_ENVIRONMENT` | `production` | Environment assumed for alerts without an `environment`/`env` label |
| `HEAL_AUDIT_LOG_PATH` | `/var/lib/self-healing-agents/audit/audit.jsonl` | Audit chain file (the chart sets one per pod) |
| `HEAL_AUDIT_KEY_FILE` | none | Ed25519 PEM audit signing key; required unless `HEAL_DEV_EPHEMERAL_KEYS=true` |
| `HEAL_DEV_EPHEMERAL_KEYS` | `false` | In-memory audit key for local use; refused in production |
| `HEAL_LOG_LEVEL` | `INFO` | Log level |
| `HEAL_OTLP_ENDPOINT` | none | OTLP gRPC endpoint for traces |
| `HEAL_HOST`, `HEAL_PORT` | `127.0.0.1`, `8080` | Bind address (the image sets `0.0.0.0`) |
| `HEAL_FORWARDED_ALLOW_IPS` | `127.0.0.1` | Proxies trusted for forwarded headers |

## Remediation behaviour

| Variable | Default | Meaning |
|---|---|---|
| `HEAL_EXECUTION_MODE` | `dry_run` | `dry_run` or `live`; live requests are refused in dry-run mode |
| `HEAL_AUTO_PROPOSE` | `true` | Propose the diagnosed action for new incidents |
| `HEAL_AUTO_EXECUTE` | `true` | Run allowed plans automatically (live only in live mode; plans awaiting approval get a dry run) |
| `HEAL_PLAN_TTL_SECONDS` | `3600` (300 to 86400) | Time a plan may wait for approval and execution |
| `HEAL_ROLLOUT_TIMEOUT_SECONDS` | `600` (30 to 3600) | Post-check deadline for rollouts |
| `HEAL_POLL_INTERVAL_SECONDS` | `5` | Post-check polling interval |
| `HEAL_PLAN_SWEEP_INTERVAL_SECONDS` | `60` | Interval of the plan expiry sweep |
| `HEAL_PROTECTED_NAMESPACES` | `["kube-system","kube-public","kube-node-lease"]` | Namespaces remediation never touches (JSON list) |

## Callers and identity

| Variable | Default | Meaning |
|---|---|---|
| `HEAL_OPERATOR_ISSUER` | required | Enterprise OIDC issuer for humans |
| `HEAL_OPERATOR_AUDIENCE` | required | Audience operator tokens must carry |
| `HEAL_OPERATOR_JWKS_URL` | required | JWKS of the operator issuer |
| `HEAL_OPERATOR_ROLES_CLAIM` | `roles` | Claim carrying `remediation-viewer`/`-operator`/`-approver` |
| `HEAL_AGENT_ID` | required | This service's SPIFFE ID in the identity fabric |
| `HEAL_FABRIC_URL` | none | Identity fabric base URL; enables fabric authorization and self-authorization |
| `HEAL_WORKLOAD_TOKEN_FILE` | `/var/run/secrets/kubernetes.io/serviceaccount/token` | Workload token for the fabric jwt-bearer grant |
| `HEAL_AGENT_ISSUER` | none | Fabric issuer for local verification (required when `HEAL_FABRIC_URL` is unset) |
| `HEAL_AGENT_JWKS_URL` | none | Fabric JWKS for local verification |
| `HEAL_AGENT_AUDIENCE` | `agent-platform` | Audience of agent credentials |
| `HEAL_AGENT_SCOPES` | `["remediation:propose","remediation:dry-run","remediation:execute"]` | Scopes of the service's own principal and fabric credential |
| `HEAL_ACCESS_POLICY_FILE` | `policies/agent-access.yaml` | Local access policy |
| `HEAL_MCP_ALLOWED_HOSTS` | host of `HEAL_PUBLIC_URL` | Host headers accepted on `/mcp` |

## Alert sources

| Variable | Default | Meaning |
|---|---|---|
| `HEAL_ALERTMANAGER_TOKEN` | none | Bearer credential Alertmanager presents; the endpoint returns 404 when unset |
| `HEAL_SNS_TOPIC_ARNS` | `[]` | Allowed SNS topic ARNs (JSON list) |

## Kubernetes and Terraform

| Variable | Default | Meaning |
|---|---|---|
| `HEAL_KUBE_API_URL` | `https://kubernetes.default.svc` | API server |
| `HEAL_KUBE_TOKEN_FILE` | service-account token path | Bearer token, re-read per request |
| `HEAL_KUBE_CA_FILE` | service-account `ca.crt` | Cluster CA |
| `HEAL_TERRAFORM_ROOT` | `/var/lib/self-healing-agents/stacks` | Root under which stack directories live |
| `HEAL_TERRAFORM_BINARY` | `terraform` | Terraform executable |
| `HEAL_TERRAFORM_TIMEOUT_SECONDS` | `1800` | Per-command timeout |

## Policy and playbooks

| Variable | Default |
|---|---|
| `HEAL_POLICY_FILE` | `policies/remediation.yaml` |
| `HEAL_PLAYBOOKS_FILE` | `policies/diagnosis-playbooks.yaml` |
| `HEAL_CHANGE_CALENDAR_FILE` | `policies/change-windows.yaml` |
| `HEAL_PROVIDERS_FILE` | none (narrator disabled) |

## Model providers (narrator)

When `HEAL_PROVIDERS_FILE=configs/providers.yaml`, these variables must be
set or loading fails: `BEDROCK_MODEL_ID`, `AWS_REGION`,
`BEDROCK_INPUT_USD_PER_MTOK`, `BEDROCK_OUTPUT_USD_PER_MTOK`,
`ANTHROPIC_MODEL`, `ANTHROPIC_API_KEY`, `ANTHROPIC_INPUT_USD_PER_MTOK`,
`ANTHROPIC_OUTPUT_USD_PER_MTOK`. Bedrock authenticates through workload
identity.

## Helm values

Chart: `deployments/helm/self-healing-infrastructure-agents`.

| Value | Variable |
|---|---|
| `heal.publicUrl` | `HEAL_PUBLIC_URL` (required) |
| `heal.environment` | `HEAL_ENVIRONMENT` |
| `heal.executionMode` | `HEAL_EXECUTION_MODE` (default `dry_run`) |
| `heal.operator.issuer`, `.audience`, `.jwksUrl` | `HEAL_OPERATOR_*` (required) |
| `heal.agentId` | `HEAL_AGENT_ID` (required) |
| `heal.fabricUrl` | `HEAL_FABRIC_URL` |
| `heal.agent.issuer`, `.jwksUrl`, `.audience` | `HEAL_AGENT_*` |
| `heal.snsTopicArns` | `HEAL_SNS_TOPIC_ARNS` |
| `heal.protectedNamespaces` | `HEAL_PROTECTED_NAMESPACES` |
| `secrets.database` | Secret with `DATABASE_URL` → `HEAL_DATABASE_URL` |
| `secrets.auditKey`, `secrets.auditKeyFile` | Audit key secret and file name → `HEAL_AUDIT_KEY_FILE` |
| `secrets.alertmanager` | Secret with the webhook credential → `HEAL_ALERTMANAGER_TOKEN` |
| `terraform.stacksClaim` | PVC mounted at `HEAL_TERRAFORM_ROOT` |
