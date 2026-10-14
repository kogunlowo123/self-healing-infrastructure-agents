"""A2A (Agent2Agent) interface: Agent Card and JSON-RPC ``message/send``.

Peers send a message whose first ``data`` part names a skill and its input:

    {"kind": "data", "data": {"skill": "analyze-terraform-plan", "plan": {...}}}

The request is authorized for that skill exactly as the HTTP API would
authorize it and answered with a completed (or failed) Task whose artifact
carries the skill's structured output. Transport-level authentication
failures are HTTP 401; malformed JSON-RPC is answered with the standard
JSON-RPC error codes.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Annotated, Any

from agentic_core.domain.identifiers import new_id
from agentic_core.observability import correlation_id
from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from self_healing_infrastructure_agents import __version__
from self_healing_infrastructure_agents.analysis.terraform_plan import analyze_plan
from self_healing_infrastructure_agents.api.deps import container
from self_healing_infrastructure_agents.domain.errors import HealingError, UnauthorizedError
from self_healing_infrastructure_agents.domain.models import ActionSpec, Principal
from self_healing_infrastructure_agents.runtime.container import Container

PROTOCOL_VERSION = "0.3.0"
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
CONTENT_TYPE_NOT_SUPPORTED = -32005

router = APIRouter(tags=["a2a"])
Deps = Annotated[Container, Depends(container)]


class Skill(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    description: str
    tags: tuple[str, ...]
    action: str = Field(exclude=True)
    resource_type: str = Field(exclude=True)


SKILLS: tuple[Skill, ...] = (
    Skill(
        id="get-incident",
        name="Get incident",
        description="Incident with alerts, diagnosis and linked plans. Input: {incident_id}.",
        tags=("incidents", "read"),
        action="incidents:read",
        resource_type="incident",
    ),
    Skill(
        id="diagnose-incident",
        name="Diagnose incident",
        description="Re-run the diagnosis playbook on fresh evidence. Input: {incident_id}.",
        tags=("diagnosis",),
        action="alerts:diagnose",
        resource_type="incident",
    ),
    Skill(
        id="analyze-terraform-plan",
        name="Analyze Terraform plan",
        description=(
            "Destructive and stateful changes, disabled safety attributes, security-sensitive "
            "changes, drift and blast radius of `terraform show -json` output. Input: {plan}."
        ),
        tags=("terraform", "risk"),
        action="terraform:analyze",
        resource_type="terraform:plan",
    ),
    Skill(
        id="propose-remediation",
        name="Propose remediation",
        description=(
            "Policy-validated remediation proposal (restart, scale, rollout undo, cordon, "
            "Terraform apply of a saved plan). Input: {action, incident_id?}."
        ),
        tags=("remediation",),
        action="remediation:propose",
        resource_type="remediation",
    ),
    Skill(
        id="get-remediation",
        name="Get remediation plan",
        description="Plan with policy outcome, approvals and executions. Input: {plan_id}.",
        tags=("remediation", "read"),
        action="remediation:read",
        resource_type="remediation",
    ),
)
_BY_ID = {s.id: s for s in SKILLS}


def agent_card(c: Container) -> dict[str, Any]:
    base = c.settings.public_url_str
    return {
        "protocolVersion": PROTOCOL_VERSION,
        "name": "Self-Healing Infrastructure Agent",
        "description": (
            "Diagnoses infrastructure alerts with versioned playbooks, analyses Terraform plans "
            "for destructive changes and blast radius, and runs policy-validated, "
            "approval-gated remediations with automatic rollback. Dry run by default."
        ),
        "url": f"{base}/a2a",
        "preferredTransport": "JSONRPC",
        "version": __version__,
        "provider": {
            "organization": "kogunlowo123",
            "url": "https://github.com/kogunlowo123/self-healing-infrastructure-agents",
        },
        "documentationUrl": (
            "https://github.com/kogunlowo123/self-healing-infrastructure-agents"
            "/blob/main/docs/architecture/a2a.md"
        ),
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": False,
        },
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [
            {
                **s.model_dump(),
                "inputModes": ["application/json"],
                "outputModes": ["application/json"],
            }
            for s in SKILLS
        ],
        "securitySchemes": {
            "agentCredential": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "Agent credential issued by the agent identity fabric",
            }
        },
        "security": [{"agentCredential": []}],
    }


@router.get("/.well-known/agent-card.json")
async def get_agent_card(c: Deps) -> dict[str, Any]:
    return agent_card(c)


def _rpc_error(rpc_id: Any, code: int, message: str, data: Any = None) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "error": error})


class DataPart(BaseModel):
    model_config = ConfigDict(extra="allow")

    kind: str
    data: dict[str, Any] | None = None


class A2AMessage(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    role: str = Field(pattern=r"^(user|agent)$")
    parts: list[DataPart] = Field(min_length=1, max_length=20)
    message_id: str = Field(alias="messageId", min_length=1, max_length=200)
    context_id: str | None = Field(default=None, alias="contextId", max_length=200)
    kind: str = "message"


class SendParams(BaseModel):
    model_config = ConfigDict(extra="allow")

    message: A2AMessage


Runner = Callable[[Principal, Container, dict[str, Any]], Awaitable[Any]]


def _require(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value or len(value) > 64:
        raise HealingError(f"input field {key!r} is required")
    return value


async def _get_incident(_: Principal, c: Container, data: dict[str, Any]) -> Any:
    return await c.incidents.get(_require(data, "incident_id"))


async def _diagnose(principal: Principal, c: Container, data: dict[str, Any]) -> Any:
    return await c.incidents.diagnose(_require(data, "incident_id"), principal=principal)


async def _analyze(_: Principal, c: Container, data: dict[str, Any]) -> Any:
    plan = data.get("plan")
    if not isinstance(plan, dict):
        raise HealingError("input field 'plan' must be the terraform show -json object")
    analysis = analyze_plan(plan)
    c.metrics.terraform_analyses.labels(analysis.risk.name.lower()).inc()
    return analysis


async def _propose(principal: Principal, c: Container, data: dict[str, Any]) -> Any:
    try:
        action = ActionSpec.model_validate(data.get("action"))
    except ValidationError as exc:
        raise HealingError(f"invalid action: {exc.error_count()} validation errors") from exc
    incident_id = data.get("incident_id")
    return await c.remediation.propose(
        action,
        principal=principal,
        incident_id=incident_id if isinstance(incident_id, str) else None,
    )


async def _get_plan(_: Principal, c: Container, data: dict[str, Any]) -> Any:
    return await c.remediation.get(_require(data, "plan_id"))


RUNNERS: dict[str, Runner] = {
    "get-incident": _get_incident,
    "diagnose-incident": _diagnose,
    "analyze-terraform-plan": _analyze,
    "propose-remediation": _propose,
    "get-remediation": _get_plan,
}


def _task(
    message: A2AMessage,
    *,
    state: str,
    at: datetime,
    skill: str,
    result: Any = None,
    error: str = "",
) -> dict[str, Any]:
    context_id = message.context_id or new_id()
    task: dict[str, Any] = {
        "kind": "task",
        "id": new_id(),
        "contextId": context_id,
        "status": {"state": state, "timestamp": at.isoformat()},
        "history": [message.model_dump(by_alias=True, mode="json")],
    }
    if state == "completed":
        payload = result.model_dump(mode="json") if isinstance(result, BaseModel) else result
        task["artifacts"] = [
            {"artifactId": new_id(), "name": skill, "parts": [{"kind": "data", "data": payload}]}
        ]
    else:
        task["status"]["message"] = {
            "kind": "message",
            "role": "agent",
            "messageId": new_id(),
            "contextId": context_id,
            "parts": [{"kind": "text", "text": error}],
        }
    return task


class _RpcError(Exception):
    def __init__(self, rpc_id: Any, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.rpc_id, self.code, self.message, self.data = rpc_id, code, message, data


def parse_request(body: bytes) -> tuple[str | int, A2AMessage, Skill, dict[str, Any]]:
    """Validate the JSON-RPC envelope and locate the skill invocation."""
    try:
        envelope = json.loads(body)
    except ValueError as exc:
        raise _RpcError(None, PARSE_ERROR, "Parse error") from exc
    if not isinstance(envelope, dict) or envelope.get("jsonrpc") != "2.0":
        raise _RpcError(None, INVALID_REQUEST, "Invalid Request")
    rpc_id = envelope.get("id")
    if not isinstance(rpc_id, str | int) or isinstance(rpc_id, bool):
        raise _RpcError(None, INVALID_REQUEST, "Invalid Request: id must be a string or number")
    if envelope.get("method") != "message/send":
        raise _RpcError(rpc_id, METHOD_NOT_FOUND, "Method not found")
    try:
        params = SendParams.model_validate(envelope.get("params"))
    except ValidationError as exc:
        raise _RpcError(rpc_id, INVALID_PARAMS, "Invalid params", exc.error_count()) from exc
    data = next((p.data for p in params.message.parts if p.kind == "data" and p.data), None)
    if data is None:
        raise _RpcError(
            rpc_id, CONTENT_TYPE_NOT_SUPPORTED, "Send a data part naming a skill", list(_BY_ID)
        )
    skill = _BY_ID.get(str(data.get("skill", "")))
    if skill is None:
        raise _RpcError(rpc_id, INVALID_PARAMS, "Unknown skill", list(_BY_ID))
    return rpc_id, params.message, skill, data


@router.post("/a2a")
async def a2a(
    request: Request, c: Deps, authorization: Annotated[str | None, Header()] = None
) -> JSONResponse:
    if not authorization:
        raise UnauthorizedError("agent credential required")
    try:
        rpc_id, message, skill, data = parse_request(await request.body())
    except _RpcError as exc:
        return _rpc_error(exc.rpc_id, exc.code, exc.message, exc.data)

    principal = await c.callers.resolve(
        authorization, action=skill.action, resource_type=skill.resource_type
    )
    try:
        result = await RUNNERS[skill.id](principal, c, data)
    except HealingError as exc:
        c.metrics.tool_calls.labels("a2a", skill.id, exc.code).inc()
        await c.audit.record(
            actor=principal.subject,
            action=f"a2a.{skill.id}",
            resource=skill.resource_type,
            outcome=f"error:{exc.code}",
            correlation_id=correlation_id(),
            details={"message": exc.message[:500]},
        )
        task = _task(
            message,
            state="failed",
            at=c.clock.now(),
            skill=skill.id,
            error=f"{exc.code}: {exc.message}",
        )
        return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": task})
    c.metrics.tool_calls.labels("a2a", skill.id, "ok").inc()
    await c.audit.record(
        actor=principal.subject,
        action=f"a2a.{skill.id}",
        resource=skill.resource_type,
        outcome="ok",
        correlation_id=correlation_id(),
    )
    task = _task(message, state="completed", at=c.clock.now(), skill=skill.id, result=result)
    return JSONResponse({"jsonrpc": "2.0", "id": rpc_id, "result": task})
