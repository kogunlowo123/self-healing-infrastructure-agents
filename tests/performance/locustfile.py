"""Load profile for a deployed instance.

Run against a staging deployment, never production:

    HEAL_LOAD_AGENT_TOKEN=<agent credential with incidents:read terraform:analyze> \
    HEAL_LOAD_ALERTMANAGER_TOKEN=<webhook credential> \
    locust -f tests/performance/locustfile.py --host https://<staging-host> \
           --users 50 --spawn-rate 10 --run-time 10m --headless

Alert storms are the stress case: Alertmanager re-sends grouped alerts, so
the mix is dominated by repeat notifications that must be correlated into
existing incidents, plus plan analysis from CI pipelines and agent reads.
The plan used is the recorded fixture under tests/fixtures/terraform.
"""

from __future__ import annotations

import json
import os
import random
from pathlib import Path

from locust import HttpUser, between, task

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
AGENT_TOKEN = os.environ.get("HEAL_LOAD_AGENT_TOKEN", "")
WEBHOOK_TOKEN = os.environ.get("HEAL_LOAD_ALERTMANAGER_TOKEN", "")
WEBHOOK = json.loads((FIXTURES / "alerts" / "alertmanager-crashloop.json").read_text("utf-8"))
PLAN = json.loads((FIXTURES / "terraform" / "aws-rds-storage-resize.plan.json").read_text("utf-8"))


class MonitoringAndAgents(HttpUser):
    wait_time = between(0.05, 0.5)

    @task(10)
    def alert_storm(self) -> None:
        body = json.loads(json.dumps(WEBHOOK))
        body["alerts"][0]["fingerprint"] = f"load-{random.randint(1, 200)}"
        self.client.post(
            "/v1/alerts/alertmanager",
            json=body,
            headers={"Authorization": f"Bearer {WEBHOOK_TOKEN}"},
            name="/v1/alerts/alertmanager",
        )

    @task(3)
    def analyze_plan(self) -> None:
        self.client.post(
            "/v1/terraform/analyze",
            json={"plan": PLAN},
            headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
            name="/v1/terraform/analyze",
        )

    @task(5)
    def list_incidents(self) -> None:
        self.client.get(
            "/v1/incidents?limit=50",
            headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
            name="/v1/incidents",
        )
