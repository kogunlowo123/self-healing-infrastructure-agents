"""Full HTTP lifecycle through the ASGI app: alert -> diagnosis -> plan -> approval ->
execution -> rollback, plus Terraform review and operations endpoints."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from self_healing_infrastructure_agents.api.app import create_app
from self_healing_infrastructure_agents.domain.models import ExecutionMode
from self_healing_infrastructure_agents.domain.ports import PodState
from self_healing_infrastructure_agents.runtime.container import Container
from tests.conftest import (
    ALERTMANAGER_TOKEN,
    PUBLIC_URL,
    START,
    FakeClock,
    FakeCluster,
    FakeIdp,
    FakeTerraform,
    agent_headers,
    load,
    make_settings,
    operator_headers,
    replicaset,
    wired,
)

pytestmark = pytest.mark.e2e


@pytest.fixture
def live_client(
    tmp_path: Path,
    cluster: FakeCluster,
    terraform: FakeTerraform,
    clock: FakeClock,
    operator_idp: FakeIdp,
    agent_idp: FakeIdp,
) -> Iterator[TestClient]:
    async def factory() -> Container:
        return await wired(
            make_settings(tmp_path, execution_mode=ExecutionMode.LIVE),
            cluster=cluster,
            terraform=terraform,
            clock=clock,
            operator_idp=operator_idp,
            agent_idp=agent_idp,
        )

    with TestClient(create_app(factory), base_url=PUBLIC_URL) as client:
        yield client


def crashlooping_release(cluster: FakeCluster) -> None:
    cluster.replicasets["payments"] = [
        replicaset("checkout", 6, owner="uid-checkout", age=timedelta(days=13)),
        replicaset("checkout", 7, owner="uid-checkout", age=timedelta(minutes=20)),
    ]
    cluster.pods["payments"] = [
        PodState(
            name=f"checkout-{i}",
            phase="Running",
            ready=False,
            restart_count=6,
            waiting_reasons=("CrashLoopBackOff",),
            started_at=START - timedelta(minutes=20),
        )
        for i in range(2)
    ]


def test_bad_release_is_rolled_back_after_two_approvals(
    live_client: TestClient, cluster: FakeCluster, operator_idp: FakeIdp
) -> None:
    crashlooping_release(cluster)
    alert = load("alerts/alertmanager-crashloop.json")
    alert["commonLabels"]["environment"] = "production"
    ingested = live_client.post(
        "/v1/alerts/alertmanager",
        json=alert,
        headers={"Authorization": f"Bearer {ALERTMANAGER_TOKEN}"},
    )
    assert ingested.status_code == 202
    [plan_id] = ingested.json()["plans"]

    viewer = operator_headers(operator_idp, "remediation-viewer")
    plan = live_client.get(f"/v1/remediations/{plan_id}", headers=viewer).json()
    assert plan["action"]["kind"] == "k8s:rollout-undo"
    assert plan["status"] == "awaiting_approval"
    assert plan["required_approvals"] == 2  # production rollback is CRITICAL
    assert plan["executions"][0]["mode"] == "dry_run"  # admission evidence for approvers

    incident = live_client.get(
        f"/v1/incidents/{ingested.json()['opened'][0]}", headers=viewer
    ).json()
    assert incident["diagnosis"]["selected"]["id"] == "bad-rollout"

    for approver in ("bob@corp.test", "carol@corp.test"):
        decided = live_client.post(
            f"/v1/remediations/{plan_id}/decision",
            json={"decision": "approve", "plan_digest": plan["digest"], "comment": "confirmed"},
            headers=operator_headers(operator_idp, "remediation-approver", sub=approver),
        )
        assert decided.status_code == 200
    assert decided.json()["status"] == "approved"

    operator = operator_headers(operator_idp, "remediation-operator")
    executed = live_client.post(
        f"/v1/remediations/{plan_id}/execute", json={"dry_run": False}, headers=operator
    )
    assert executed.status_code == 200
    assert executed.json()["status"] == "succeeded"
    template = cluster.deployments[("payments", "checkout")].template
    assert template["spec"]["containers"][0]["image"].endswith(":r6")
    resolved = live_client.get(
        f"/v1/incidents/{ingested.json()['opened'][0]}", headers=viewer
    ).json()
    assert resolved["status"] == "resolved"

    metrics = live_client.get("/metrics").text
    assert 'heal_remediations_total{action="k8s:rollout-undo",mode="live",outcome="succeeded"}' in (
        metrics
    )


def test_failed_post_check_rolls_back_and_escalates(
    live_client: TestClient, cluster: FakeCluster, operator_idp: FakeIdp
) -> None:
    cluster.outcomes = deque(["stuck", "complete"])
    operator = operator_headers(operator_idp, "remediation-operator")
    plan = live_client.post(
        "/v1/remediations",
        json={
            "action": {
                "kind": "k8s:scale",
                "replicas": 6,
                "reason": "capacity",
                "target": {
                    "kind": "deployment",
                    "name": "checkout",
                    "namespace": "payments",
                    "environment": "staging",
                },
            }
        },
        headers=operator,
    ).json()
    assert plan["status"] == "proposed"
    result = live_client.post(
        f"/v1/remediations/{plan['id']}/execute", json={"dry_run": False}, headers=operator
    ).json()
    assert result["status"] == "rolled_back"
    assert cluster.deployments[("payments", "checkout")].replicas == 4
    steps = [s["name"] for s in result["executions"][-1]["steps"]]
    assert steps[-2:] == ["rollback", "rollback-check"]


def test_terraform_review_and_apply(
    live_client: TestClient,
    terraform: FakeTerraform,
    operator_idp: FakeIdp,
    agent_idp: FakeIdp,
) -> None:
    analysis = live_client.post(
        "/v1/terraform/analyze",
        json={"plan": load("terraform/aws-rds-replace-and-bucket-delete.plan.json")},
        headers=agent_headers(agent_idp, "terraform:analyze"),
    )
    assert analysis.status_code == 200
    assert analysis.json()["risk"] == 4
    invalid = live_client.post(
        "/v1/terraform/analyze",
        json={"plan": {"format_version": "9"}},
        headers=agent_headers(agent_idp, "terraform:analyze"),
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"] == "invalid_plan"

    operator = operator_headers(operator_idp, "remediation-operator")
    plan = live_client.post(
        "/v1/remediations",
        json={
            "action": {
                "kind": "terraform:apply",
                "plan_file": "resize.tfplan",
                "reason": "orders database is running out of storage",
                "target": {
                    "kind": "terraform_stack",
                    "name": "rds/orders",
                    "environment": "production",
                },
            }
        },
        headers=operator,
    ).json()
    assert plan["status"] == "awaiting_approval"
    assert plan["terraform"]["changes"][1]["changed_attributes"] == ["allocated_storage"]
    live_client.post(
        f"/v1/remediations/{plan['id']}/decision",
        json={"decision": "approve", "plan_digest": plan["digest"], "comment": "capacity review"},
        headers=operator_headers(operator_idp, "remediation-approver", sub="dba@corp.test"),
    )
    done = live_client.post(
        f"/v1/remediations/{plan['id']}/execute", json={"dry_run": False}, headers=operator
    ).json()
    assert done["status"] == "succeeded"
    assert ("apply", "rds/orders", "resize.tfplan") in terraform.calls


def test_listing_filtering_and_errors(client: TestClient, operator_idp: FakeIdp) -> None:
    viewer = operator_headers(operator_idp, "remediation-viewer")
    assert client.get("/v1/incidents?status=open&limit=5", headers=viewer).json()["items"] == []
    assert client.get("/v1/remediations?status=approved", headers=viewer).json()["limit"] == 100
    missing = client.get("/v1/incidents/does-not-exist", headers=viewer)
    assert missing.status_code == 404
    assert missing.json()["error"] == "not_found"
    assert client.get("/v1/remediations/nope", headers=viewer).status_code == 404
    bad = client.get("/v1/incidents?limit=0", headers=viewer)
    assert bad.status_code == 422
    assert bad.json()["error"] == "invalid_request"
    diagnose = client.post(
        "/v1/incidents/nope/diagnose",
        headers=operator_headers(operator_idp, "remediation-operator"),
    )
    assert diagnose.status_code == 404


def test_operations_endpoints(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ready", "execution_mode": "dry_run"}
    assert "heal_http_request_duration_seconds" in client.get("/metrics").text
