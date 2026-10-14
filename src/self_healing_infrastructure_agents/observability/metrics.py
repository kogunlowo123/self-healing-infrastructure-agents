"""Service metrics exposed on /metrics in Prometheus text format (own registry)."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram


class HealingMetrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self.requests = Histogram(
            "heal_http_request_duration_seconds",
            "HTTP request latency",
            ["method", "route", "status"],
            registry=self.registry,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
        )
        self.alerts = Counter(
            "heal_alerts_received_total",
            "Alerts accepted from monitoring sources",
            ["source", "status"],
            registry=self.registry,
        )
        self.webhook_rejections = Counter(
            "heal_webhook_rejections_total",
            "Alert notifications rejected before ingestion",
            ["source", "reason"],
            registry=self.registry,
        )
        self.incidents_opened = Counter(
            "heal_incidents_opened_total",
            "Incidents opened",
            ["severity"],
            registry=self.registry,
        )
        self.diagnoses = Counter(
            "heal_diagnoses_total",
            "Diagnoses by playbook and whether they escalated",
            ["playbook", "outcome"],
            registry=self.registry,
        )
        self.policy_decisions = Counter(
            "heal_policy_decisions_total",
            "Remediation policy decisions",
            ["action", "decision"],
            registry=self.registry,
        )
        self.approvals = Counter(
            "heal_approvals_total",
            "Approval decisions recorded",
            ["decision"],
            registry=self.registry,
        )
        self.remediations = Counter(
            "heal_remediations_total",
            "Remediation executions",
            ["action", "mode", "outcome"],
            registry=self.registry,
        )
        self.remediation_duration = Histogram(
            "heal_remediation_duration_seconds",
            "Wall time of remediation executions including post-checks",
            ["action", "mode"],
            registry=self.registry,
            buckets=(1, 5, 15, 30, 60, 120, 300, 600, 1200, 1800),
        )
        self.plans_expired = Counter(
            "heal_plans_expired_total",
            "Plans that expired before execution",
            registry=self.registry,
        )
        self.terraform_analyses = Counter(
            "heal_terraform_analyses_total",
            "Terraform plans analysed, by risk tier",
            ["risk"],
            registry=self.registry,
        )
        self.tool_calls = Counter(
            "heal_agent_tool_calls_total",
            "MCP tool and A2A skill invocations",
            ["interface", "name", "outcome"],
            registry=self.registry,
        )
