"""MCP (streamable HTTP) and A2A (agent card + JSON-RPC message/send) end to end."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.conftest import FakeIdp, agent_headers, load, operator_headers

pytestmark = pytest.mark.e2e

MCP_HEADERS = {
    "accept": "application/json, text/event-stream",
    "content-type": "application/json",
    "mcp-protocol-version": "2025-06-18",
}


def rpc(client: TestClient, method: str, params: dict[str, Any], headers: dict[str, str]) -> Any:
    response = client.post(
        "/mcp/",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        headers={**MCP_HEADERS, **headers},
    )
    assert response.status_code == 200, response.text
    return response.json()


class TestMcp:
    def test_initialize_and_list_tools(self, client: TestClient, agent_idp: FakeIdp) -> None:
        auth = agent_headers(agent_idp, "incidents:read")
        init = rpc(
            client,
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "sre-agent", "version": "1"},
            },
            auth,
        )
        assert init["result"]["serverInfo"]["name"] == "self-healing-infrastructure-agents"
        tools = {t["name"]: t for t in rpc(client, "tools/list", {}, auth)["result"]["tools"]}
        assert set(tools) == {
            "list_incidents",
            "get_incident",
            "diagnose_incident",
            "analyze_terraform_plan",
            "propose_remediation",
            "list_remediations",
            "dry_run_remediation",
            "execute_remediation",
        }
        assert tools["execute_remediation"]["annotations"]["destructiveHint"] is True
        assert "outputSchema" in tools["analyze_terraform_plan"]
        assert "action" in tools["propose_remediation"]["inputSchema"]["properties"]

    def test_tool_calls_are_authorized_and_audited(
        self, client: TestClient, agent_idp: FakeIdp
    ) -> None:
        analyst = agent_headers(agent_idp, "terraform:analyze")
        result = rpc(
            client,
            "tools/call",
            {
                "name": "analyze_terraform_plan",
                "arguments": {"plan": load("terraform/aws-rds-protection-disabled.plan.json")},
            },
            analyst,
        )["result"]
        assert result["isError"] is False
        assert result["structuredContent"]["protection_disabled"]

        denied = rpc(client, "tools/call", {"name": "list_incidents", "arguments": {}}, analyst)[
            "result"
        ]
        assert denied["isError"] is True
        assert "forbidden" in denied["content"][0]["text"]

        settings = client.app.state.container.settings  # type: ignore[attr-defined]
        trail = [
            json.loads(line)
            for line in settings.audit_log_path.read_text(encoding="utf-8").splitlines()
        ]
        outcomes = {(e["action"], e["outcome"]) for e in trail}
        assert ("mcp.analyze_terraform_plan", "ok") in outcomes
        assert ("mcp.list_incidents", "error:forbidden") in outcomes
        metrics = client.get("/metrics").text
        assert (
            'heal_agent_tool_calls_total{interface="mcp",name="analyze_terraform_plan",'
            'outcome="ok"} 1.0'
        ) in metrics
        assert (
            'heal_agent_tool_calls_total{interface="mcp",name="list_incidents",'
            'outcome="forbidden"} 1.0'
        ) in metrics

    def test_propose_dry_run_and_live_refusal(
        self, client: TestClient, agent_idp: FakeIdp, operator_idp: FakeIdp
    ) -> None:
        agent = agent_headers(agent_idp, "remediation:*", "incidents:read")
        action = {
            "kind": "k8s:restart",
            "reason": "memory leak",
            "target": {
                "kind": "deployment",
                "name": "checkout",
                "namespace": "payments",
                "environment": "staging",
            },
        }
        proposed = rpc(
            client,
            "tools/call",
            {"name": "propose_remediation", "arguments": {"action": action}},
            agent,
        )["result"]["structuredContent"]
        assert proposed["status"] == "proposed"
        dry = rpc(
            client,
            "tools/call",
            {"name": "dry_run_remediation", "arguments": {"plan_id": proposed["id"]}},
            agent,
        )["result"]["structuredContent"]
        assert dry["executions"][-1]["mode"] == "dry_run"
        live = rpc(
            client,
            "tools/call",
            {"name": "execute_remediation", "arguments": {"plan_id": proposed["id"]}},
            agent,
        )["result"]
        assert live["isError"] is True
        assert "live_execution_disabled" in live["content"][0]["text"]
        listed = rpc(client, "tools/call", {"name": "list_remediations", "arguments": {}}, agent)[
            "result"
        ]["structuredContent"]
        assert listed["items"][0]["id"] == proposed["id"]

    def test_incident_tools(self, client: TestClient, agent_idp: FakeIdp) -> None:
        from tests.conftest import ALERTMANAGER_TOKEN

        opened = client.post(
            "/v1/alerts/alertmanager",
            json=load("alerts/alertmanager-crashloop.json"),
            headers={"Authorization": f"Bearer {ALERTMANAGER_TOKEN}"},
        ).json()["opened"][0]
        agent = agent_headers(agent_idp, "incidents:read", "alerts:diagnose")
        listed = rpc(
            client,
            "tools/call",
            {"name": "list_incidents", "arguments": {"status": "escalated"}},
            agent,
        )
        assert listed["result"]["structuredContent"]["items"][0]["id"] == opened
        got = rpc(
            client,
            "tools/call",
            {"name": "get_incident", "arguments": {"incident_id": opened}},
            agent,
        )
        assert got["result"]["structuredContent"]["fingerprint"] == "am:8f2b7c1d9e4a6b30"
        again = rpc(
            client,
            "tools/call",
            {"name": "diagnose_incident", "arguments": {"incident_id": opened}},
            agent,
        )
        assert again["result"]["structuredContent"]["diagnosis"]["playbook_id"] == "crashloop"

    def test_unauthenticated_tool_call(self, client: TestClient) -> None:
        result = rpc(client, "tools/call", {"name": "list_incidents", "arguments": {}}, {})
        assert result["result"]["isError"] is True
        assert "unauthorized" in result["result"]["content"][0]["text"]


def message(data: dict[str, Any] | None = None, **params: Any) -> dict[str, Any]:
    parts = (
        [{"kind": "data", "data": data}]
        if data is not None
        else [{"kind": "text", "text": "hello"}]
    )
    return {
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "message/send",
        "params": {
            "message": {"role": "user", "messageId": "m-1", "contextId": "ctx-9", "parts": parts},
            **params,
        },
    }


class TestA2A:
    def test_agent_card(self, client: TestClient) -> None:
        card = client.get("/.well-known/agent-card.json").json()
        for key in (
            "name",
            "description",
            "url",
            "version",
            "capabilities",
            "skills",
            "securitySchemes",
        ):
            assert key in card
        assert card["url"] == "https://heal.corp.test/a2a"
        assert card["securitySchemes"]["agentCredential"]["scheme"] == "bearer"
        assert {s["id"] for s in card["skills"]} >= {
            "analyze-terraform-plan",
            "propose-remediation",
        }
        assert "action" not in card["skills"][0]

    def test_analyze_skill(self, client: TestClient, agent_idp: FakeIdp) -> None:
        response = client.post(
            "/a2a",
            json=message(
                {
                    "skill": "analyze-terraform-plan",
                    "plan": load("terraform/aws-rds-storage-resize.plan.json"),
                }
            ),
            headers=agent_headers(agent_idp, "terraform:analyze"),
        )
        task = response.json()["result"]
        assert task["kind"] == "task"
        assert task["status"]["state"] == "completed"
        assert task["contextId"] == "ctx-9"
        data = task["artifacts"][0]["parts"][0]["data"]
        assert data["risk"] == 1
        assert data["stateful_deletes"] == []

    def test_propose_and_read_skills(self, client: TestClient, agent_idp: FakeIdp) -> None:
        headers = agent_headers(agent_idp, "remediation:*", "incidents:read")
        action = {
            "kind": "k8s:cordon",
            "reason": "disk pressure",
            "target": {"kind": "node", "name": "node-a", "environment": "staging"},
        }
        proposed = client.post(
            "/a2a",
            json=message({"skill": "propose-remediation", "action": action}),
            headers=headers,
        ).json()
        plan = proposed["result"]["artifacts"][0]["parts"][0]["data"]
        assert plan["status"] == "proposed"
        got = client.post(
            "/a2a",
            json=message({"skill": "get-remediation", "plan_id": plan["id"]}),
            headers=headers,
        ).json()
        assert got["result"]["status"]["state"] == "completed"
        failed = client.post(
            "/a2a",
            json=message({"skill": "get-incident", "incident_id": "missing"}),
            headers=headers,
        ).json()
        assert failed["result"]["status"]["state"] == "failed"
        assert "not_found" in failed["result"]["status"]["message"]["parts"][0]["text"]
        invalid = client.post(
            "/a2a",
            json=message({"skill": "propose-remediation", "action": {"kind": "k8s:nope"}}),
            headers=headers,
        ).json()
        assert invalid["result"]["status"]["state"] == "failed"
        diagnose = client.post(
            "/a2a",
            json=message({"skill": "diagnose-incident"}),
            headers=agent_headers(agent_idp, "alerts:diagnose"),
        ).json()
        assert diagnose["result"]["status"]["state"] == "failed"
        analyze = client.post(
            "/a2a",
            json=message({"skill": "analyze-terraform-plan", "plan": "not-a-plan"}),
            headers=agent_headers(agent_idp, "terraform:analyze"),
        ).json()
        assert analyze["result"]["status"]["state"] == "failed"

    @pytest.mark.parametrize(
        ("body", "code"),
        [
            (b"{", -32700),
            (b"[]", -32600),
            (b'{"jsonrpc": "2.0", "id": true, "method": "message/send"}', -32600),
            (b'{"jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": {}}', -32601),
            (b'{"jsonrpc": "2.0", "id": 1, "method": "message/send", "params": {}}', -32602),
        ],
    )
    def test_json_rpc_errors(
        self, client: TestClient, agent_idp: FakeIdp, body: bytes, code: int
    ) -> None:
        response = client.post(
            "/a2a", content=body, headers=agent_headers(agent_idp, "incidents:read")
        )
        assert response.json()["error"]["code"] == code

    def test_skill_routing_errors(self, client: TestClient, agent_idp: FakeIdp) -> None:
        headers = agent_headers(agent_idp, "incidents:read")
        text_only = client.post("/a2a", json=message(None), headers=headers).json()
        assert text_only["error"]["code"] == -32005
        unknown = client.post("/a2a", json=message({"skill": "rm-rf"}), headers=headers).json()
        assert unknown["error"]["code"] == -32602

    def test_authentication_and_authorization(
        self, client: TestClient, agent_idp: FakeIdp, operator_idp: FakeIdp
    ) -> None:
        assert client.post("/a2a", json=message({"skill": "get-incident"})).status_code == 401
        forbidden = client.post(
            "/a2a",
            json=message({"skill": "propose-remediation", "action": {}}),
            headers=agent_headers(agent_idp, "incidents:read"),
        )
        assert forbidden.status_code == 403
        operator = client.post(
            "/a2a",
            json=message({"skill": "get-incident", "incident_id": "x"}),
            headers=operator_headers(operator_idp, "remediation-viewer"),
        )
        assert operator.json()["result"]["status"]["state"] == "failed"  # not found, but allowed
