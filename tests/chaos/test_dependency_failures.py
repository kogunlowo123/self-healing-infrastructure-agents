"""Fault injection: dependencies break; the service fails closed and never acts blind."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from self_healing_infrastructure_agents.api.app import create_app, expire_plans_forever
from self_healing_infrastructure_agents.domain.errors import IntegrationUnavailableError
from self_healing_infrastructure_agents.domain.models import ExecutionMode, PlanStatus
from self_healing_infrastructure_agents.infrastructure.database import make_engine
from self_healing_infrastructure_agents.runtime.container import Container
from tests.conftest import (
    ALERTMANAGER_TOKEN,
    PUBLIC_URL,
    FakeClock,
    FakeCluster,
    FakeIdp,
    FakeTerraform,
    agent_headers,
    load,
    make_settings,
    operator_headers,
    wired,
)
from tests.unit.test_services import OPERATOR, restart, tf

pytestmark = pytest.mark.chaos


def test_database_outage_flips_readiness(client: TestClient) -> None:
    container = client.app.state.container  # type: ignore[attr-defined]
    assert client.get("/readyz").status_code == 200
    healthy = container.engine
    container.engine = make_engine("sqlite+aiosqlite:////nonexistent/dir/heal.sqlite")
    try:
        assert client.get("/readyz").status_code == 503
        assert client.get("/healthz").status_code == 200  # liveness unaffected
    finally:
        container.engine = healthy


def test_kubernetes_outage_escalates_instead_of_acting(
    client: TestClient, cluster: FakeCluster, operator_idp: FakeIdp
) -> None:
    cluster.unavailable = {"*"}
    response = client.post(
        "/v1/alerts/alertmanager",
        json=load("alerts/alertmanager-crashloop.json"),
        headers={"Authorization": f"Bearer {ALERTMANAGER_TOKEN}"},
    )
    assert response.status_code == 202
    assert response.json()["plans"] == []
    incident = client.get(
        f"/v1/incidents/{response.json()['opened'][0]}",
        headers=operator_headers(operator_idp, "remediation-viewer"),
    ).json()
    assert incident["status"] == "escalated"
    assert len(incident["diagnosis"]["evidence"]["errors"]) == 3
    assert cluster.calls == []


async def test_audit_failure_blocks_remediation(container: Container) -> None:
    async def broken_append(_: object) -> None:
        raise OSError("audit volume full")

    container.audit._sink.append = broken_append  # type: ignore[method-assign]
    with pytest.raises(OSError, match="audit volume full"):
        await container.remediation.propose(restart(), principal=OPERATOR)


async def test_terraform_unavailable_at_apply(
    tmp_path: Path,
    cluster: FakeCluster,
    terraform: FakeTerraform,
    clock: FakeClock,
    operator_idp: FakeIdp,
    agent_idp: FakeIdp,
) -> None:
    c = await wired(
        make_settings(tmp_path, execution_mode=ExecutionMode.LIVE),
        cluster=cluster,
        terraform=terraform,
        clock=clock,
        operator_idp=operator_idp,
        agent_idp=agent_idp,
    )
    try:
        plan = await c.remediation.propose(tf(), principal=OPERATOR)
        from tests.unit.test_services import APPROVER_1, approve

        approved = await approve(c, plan, APPROVER_1)

        async def unavailable(stack: str, plan_file: str) -> object:
            raise IntegrationUnavailableError("terraform binary missing")

        terraform.apply = unavailable  # type: ignore[assignment,method-assign]
        result = await c.remediation.execute(approved.id, principal=OPERATOR, dry_run=False)
        assert result.status is PlanStatus.FAILED
        assert result.executions[-1].outcome.value == "rollback_failed"  # no rollback stack
    finally:
        await c.aclose()


@pytest.fixture
def fabric_down_client(
    tmp_path: Path,
    cluster: FakeCluster,
    terraform: FakeTerraform,
    clock: FakeClock,
    operator_idp: FakeIdp,
    agent_idp: FakeIdp,
) -> Iterator[TestClient]:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("fabric unreachable", request=request)

    async def factory() -> Container:
        return await wired(
            make_settings(
                tmp_path,
                fabric_url="https://identity.corp.test",
                agent_issuer=None,
                agent_jwks_url=None,
            ),
            cluster=cluster,
            terraform=terraform,
            clock=clock,
            operator_idp=operator_idp,
            agent_idp=agent_idp,
            http=httpx.AsyncClient(transport=httpx.MockTransport(down)),
        )

    with TestClient(create_app(factory), base_url=PUBLIC_URL) as client:
        yield client


def test_identity_fabric_outage_fails_closed(
    fabric_down_client: TestClient, agent_idp: FakeIdp, operator_idp: FakeIdp
) -> None:
    response = fabric_down_client.get(
        "/v1/incidents", headers=agent_headers(agent_idp, "incidents:read")
    )
    assert response.status_code == 503
    assert response.json()["error"] == "integration_unavailable"
    # Human operators authenticate against the enterprise IdP and are unaffected.
    assert (
        fabric_down_client.get(
            "/v1/incidents", headers=operator_headers(operator_idp, "remediation-viewer")
        ).status_code
        == 200
    )


async def test_expiry_sweeper_survives_failures(container: Container) -> None:
    calls = {"n": 0}

    async def flaky() -> int:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("database blip")
        return 0

    container.remediation.expire_stale = flaky  # type: ignore[method-assign]

    async def stop_after_two(_: float) -> None:
        if calls["n"] >= 2:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await expire_plans_forever(container, 1.0, sleep=stop_after_two)
    assert calls["n"] == 2


def test_lifespan_sweeper_runs(
    tmp_path: Path,
    cluster: FakeCluster,
    terraform: FakeTerraform,
    clock: FakeClock,
    operator_idp: FakeIdp,
    agent_idp: FakeIdp,
) -> None:
    async def factory() -> Container:
        return await wired(
            make_settings(tmp_path),
            cluster=cluster,
            terraform=terraform,
            clock=clock,
            operator_idp=operator_idp,
            agent_idp=agent_idp,
        )

    with TestClient(create_app(factory, sweep_interval_s=0.01), base_url=PUBLIC_URL) as client:
        assert client.get("/healthz").status_code == 200
