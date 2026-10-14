"""Kubernetes API adapter against recorded API server wire documents."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from self_healing_infrastructure_agents.domain.errors import (
    ConflictError,
    ForbiddenError,
    IntegrationError,
    IntegrationUnavailableError,
    TargetNotFoundError,
)
from self_healing_infrastructure_agents.integrations.kubernetes import (
    JSON_PATCH,
    MERGE,
    RESTARTED_AT,
    STRATEGIC,
    KubernetesApiClient,
    file_token,
)
from tests.conftest import load

Handler = Callable[[httpx.Request], httpx.Response]


def client(handler: Handler, token: str = "sa-token-1") -> KubernetesApiClient:
    http = httpx.AsyncClient(
        base_url="https://kubernetes.default.svc", transport=httpx.MockTransport(handler)
    )
    return KubernetesApiClient(http, token=lambda: token)


class Recorder:
    def __init__(self, routes: dict[tuple[str, str], Any]) -> None:
        self.routes = routes
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.routes[(request.method, request.url.path)]
        if isinstance(answer, httpx.Response):
            return answer
        return httpx.Response(200, json=answer)


DEPLOYMENT = "/apis/apps/v1/namespaces/payments/deployments/checkout"


class TestReads:
    async def test_deployment_parsing(self) -> None:
        recorder = Recorder({("GET", DEPLOYMENT): load("kubernetes/deployment.json")})
        state = await client(recorder).get_deployment("payments", "checkout")
        assert state.revision == 7
        assert state.replicas == 4
        assert state.ready_replicas == 2
        assert state.progress_deadline_exceeded
        assert not state.rollout_complete
        assert state.selector == {"app.kubernetes.io/name": "checkout"}
        assert state.resource_version == "48211937"
        request = recorder.requests[0]
        assert request.headers["authorization"] == "Bearer sa-token-1"

    async def test_replicasets_and_pods(self) -> None:
        recorder = Recorder(
            {
                ("GET", "/apis/apps/v1/namespaces/payments/replicasets"): load(
                    "kubernetes/replicasets.json"
                ),
                ("GET", "/api/v1/namespaces/payments/pods"): load("kubernetes/pods.json"),
            }
        )
        api = client(recorder)
        replicasets = await api.list_replicasets("payments", {"app.kubernetes.io/name": "checkout"})
        assert [rs.revision for rs in replicasets] == [6, 7]
        assert replicasets[0].owner_uid == "5f0c2e8a-6b1d-4a59-9a6f-0d8b3c4e7a21"
        assert replicasets[1].created_at == datetime(2026, 10, 14, 13, 38, 45, tzinfo=UTC)
        pods = await api.list_pods("payments", {"app.kubernetes.io/name": "checkout"})
        assert pods[0].waiting_reasons == ("CrashLoopBackOff",)
        assert pods[0].restart_count == 6
        assert not pods[0].ready
        assert pods[3].last_terminations[0].reason == "OOMKilled"
        assert pods[2].ready
        assert recorder.requests[0].url.params["labelSelector"] == "app.kubernetes.io/name=checkout"

    async def test_nodes(self) -> None:
        recorder = Recorder(
            {
                ("GET", "/api/v1/nodes/ip-10-20-31-17.ec2.internal"): load("kubernetes/node.json"),
                ("GET", "/api/v1/nodes"): load("kubernetes/nodes.json"),
            }
        )
        api = client(recorder)
        node = await api.get_node("ip-10-20-31-17.ec2.internal")
        assert node.ready
        assert node.pressure == ("DiskPressure",)
        nodes = await api.list_nodes()
        assert sum(n.unschedulable for n in nodes) == 1
        assert sum(n.control_plane for n in nodes) == 1


class TestMutations:
    async def test_restart_is_strategic_merge_with_dry_run(self) -> None:
        recorder = Recorder({("PATCH", DEPLOYMENT): load("kubernetes/deployment.json")})
        at = datetime(2026, 10, 14, 14, 0, tzinfo=UTC)
        await client(recorder).restart_deployment("payments", "checkout", at=at, dry_run=True)
        request = recorder.requests[0]
        assert request.headers["content-type"] == STRATEGIC
        assert request.url.params["dryRun"] == "All"
        assert request.url.params["fieldManager"] == "self-healing-infrastructure-agents"
        body = json.loads(request.content)
        assert body["spec"]["template"]["metadata"]["annotations"][RESTARTED_AT] == at.isoformat()

    async def test_scale_uses_subresource(self) -> None:
        recorder = Recorder(
            {
                ("PATCH", DEPLOYMENT + "/scale"): load("kubernetes/scale.json"),
                ("GET", DEPLOYMENT): load("kubernetes/deployment.json"),
            }
        )
        api = client(recorder)
        dry = await api.scale_deployment("payments", "checkout", 8, dry_run=True)
        assert dry.replicas == 8  # would-be spec reported for dry runs
        live = await api.scale_deployment("payments", "checkout", 8, dry_run=False)
        assert live.replicas == 4  # the live object as returned by the API server
        patch = recorder.requests[0]
        assert patch.headers["content-type"] == MERGE
        assert json.loads(patch.content) == {"spec": {"replicas": 8}}
        assert "dryRun" not in recorder.requests[2].url.params

    async def test_template_replace_has_concurrency_precondition(self) -> None:
        recorder = Recorder({("PATCH", DEPLOYMENT): load("kubernetes/deployment.json")})
        await client(recorder).replace_pod_template(
            "payments", "checkout", {"metadata": {}}, resource_version="48211937", dry_run=False
        )
        request = recorder.requests[0]
        assert request.headers["content-type"] == JSON_PATCH
        assert json.loads(request.content) == [
            {"op": "test", "path": "/metadata/resourceVersion", "value": "48211937"},
            {"op": "replace", "path": "/spec/template", "value": {"metadata": {}}},
        ]

    async def test_cordon(self) -> None:
        node = load("kubernetes/node.json")
        node["spec"]["unschedulable"] = True
        recorder = Recorder({("PATCH", "/api/v1/nodes/ip-10-20-31-17.ec2.internal"): node})
        state = await client(recorder).set_unschedulable(
            "ip-10-20-31-17.ec2.internal", True, dry_run=False
        )
        assert state.unschedulable
        assert json.loads(recorder.requests[0].content) == {"spec": {"unschedulable": True}}


class TestErrors:
    @pytest.mark.parametrize(
        ("status", "method", "error"),
        [
            (404, "GET", TargetNotFoundError),
            (403, "GET", ForbiddenError),
            (401, "GET", ForbiddenError),
            (422, "PATCH", ConflictError),
            (409, "PATCH", ConflictError),
            (429, "GET", IntegrationUnavailableError),
            (503, "GET", IntegrationUnavailableError),
            (400, "GET", IntegrationError),
        ],
    )
    async def test_status_mapping(self, status: int, method: str, error: type[Exception]) -> None:
        response = httpx.Response(status, json=load("kubernetes/status-invalid.json"))
        api = client(lambda _: response)
        call = (
            api.get_deployment("payments", "checkout")
            if method == "GET"
            else api.set_unschedulable("node-a", True, dry_run=False)
        )
        with pytest.raises(error):
            await call

    async def test_non_json_error_body(self) -> None:
        api = client(lambda _: httpx.Response(400, text="bad request"))
        with pytest.raises(IntegrationError, match="bad request"):
            await api.get_node("node-a")

    async def test_transport_failures(self) -> None:
        def timeout(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("slow", request=request)

        def refused(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        with pytest.raises(IntegrationUnavailableError, match="timeout"):
            await client(timeout).list_nodes()
        with pytest.raises(IntegrationUnavailableError, match="unreachable"):
            await client(refused).list_nodes()

    async def test_malformed_object(self) -> None:
        api = client(lambda _: httpx.Response(200, json={"metadata": {}}))
        with pytest.raises(IntegrationError, match="unexpected Kubernetes API object"):
            await api.get_deployment("payments", "checkout")

    async def test_bad_revision_annotation(self) -> None:
        document = load("kubernetes/deployment.json")
        document["metadata"]["annotations"]["deployment.kubernetes.io/revision"] = "seven"
        state = await client(lambda _: httpx.Response(200, json=document)).get_deployment(
            "payments", "checkout"
        )
        assert state.revision is None


def test_file_token_rereads_rotation(tmp_path: Path) -> None:
    path = tmp_path / "token"
    path.write_text("first\n", encoding="utf-8")
    read = file_token(path)
    assert read() == "first"
    path.write_text("second", encoding="utf-8")
    assert read() == "second"
