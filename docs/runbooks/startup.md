# Startup and deployment

## Prerequisites

1. Cloud infrastructure from `deployments/terraform/<cloud>` applied: database,
   key, secret store, audit storage, workload identity.
2. The service registered in the agent identity fabric with its SPIFFE ID
   and scopes (`k8s:restart k8s:scale k8s:rollout-undo k8s:cordon
   k8s:uncordon terraform:apply` plus `remediation:*`).
3. Secrets in the secret manager: database URL, Ed25519 audit key, the
   Alertmanager webhook credential.
4. A `terraform-stacks` persistent volume claim the delivery pipeline
   populates with stack directories and saved plans.

## Install

```bash
kubectl apply -k deployments/kubernetes            # namespace, Alertmanager route, secret sync
helm install heal oci://ghcr.io/kogunlowo123/charts/self-healing-infrastructure-agents \
  --version 0.1.0 -n self-healing -f <environment>.yaml
```

The chart refuses to render until required values are set (public URL,
operator issuer/audience/JWKS URL, agent ID, fabric URL or agent issuer and
JWKS URL, audit key file name).

## Verify

```bash
kubectl -n self-healing rollout status statefulset/heal-self-healing-infrastructure-agents
curl -s https://<public host>/readyz          # {"status":"ready","execution_mode":"dry_run"}
curl -s https://<public host>/.well-known/agent-card.json | jq .name
```

## Connect alert sources

- Alertmanager: a `webhook_configs` receiver pointing at
  `/v1/alerts/alertmanager` with `http_config.authorization.credentials`
  set from the shared webhook secret. With the Prometheus Operator this is
  `deployments/kubernetes/alertmanager-config.yaml` (an `AlertmanagerConfig`
  routing the alert names the playbooks cover). Route only alerts with
  playbooks or that you want tracked.
- CloudWatch: an SNS topic with `SignatureVersion=2`, its ARN in
  `heal.snsTopicArns`, and an HTTPS subscription to `/v1/alerts/cloudwatch`.
  On AWS, `deployments/terraform/aws` creates the KMS-encrypted topic, its
  publish policy and the subscription (output `alarms_topic_arn`).
  The service confirms the subscription after verifying it.

The service starts in dry-run mode. Moving an environment to live execution
follows [enabling-live-execution.md](enabling-live-execution.md).
