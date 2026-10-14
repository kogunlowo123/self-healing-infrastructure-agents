"""MCP server exposing the self-healing tools (official MCP Python SDK, streamable HTTP).

Each tool has typed input and output schemas derived from Pydantic models,
authorizes the caller from the request's bearer token through the same
CallerResolver as the HTTP API, and writes an audit event for every call,
successful or not. The server runs stateless with JSON responses so any
replica can serve any request.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from agentic_core.observability import correlation_id
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations
from pydantic import Field

from self_healing_infrastructure_agents import __version__
from self_healing_infrastructure_agents.analysis.terraform_plan import analyze_plan
from self_healing_infrastructure_agents.api.schemas import IncidentList, PlanList
from self_healing_infrastructure_agents.domain.errors import HealingError
from self_healing_infrastructure_agents.domain.models import (
    ActionSpec,
    Incident,
    IncidentStatus,
    PlanAnalysis,
    PlanStatus,
    Principal,
    RemediationPlan,
)
from self_healing_infrastructure_agents.runtime.container import Container

ContainerGetter = Callable[[], Container]

INSTRUCTIONS = (
    "Tools for self-healing cloud infrastructure. Read incidents and their diagnoses, "
    "analyse Terraform plans for destructive changes and blast radius, propose "
    "remediations and run server-side dry runs. Every proposal is checked against the "
    "remediation policy; live changes in production and every Terraform apply wait for "
    "human approval, which cannot be granted through these tools."
)

_READ = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)
_WRITE = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False)
_LIVE = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False)


def build_mcp(get_container: ContainerGetter) -> MCPServer[Any]:
    server: MCPServer[Any] = MCPServer(
        name="self-healing-infrastructure-agents",
        version=__version__,
        instructions=INSTRUCTIONS,
        log_level="WARNING",
    )

    async def call[T](
        ctx: Context,
        name: str,
        *,
        action: str,
        resource_type: str,
        resource_id: str,
        run: Callable[[Principal, Container], Awaitable[T]],
    ) -> T:
        c = get_container()
        headers = ctx.headers or {}
        actor = "anonymous"
        try:
            principal = await c.callers.resolve(
                headers.get("authorization"),
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
            )
            actor = principal.subject
            result = await run(principal, c)
        except HealingError as exc:
            c.metrics.tool_calls.labels("mcp", name, exc.code).inc()
            await c.audit.record(
                actor=actor,
                action=f"mcp.{name}",
                resource=resource_id,
                outcome=f"error:{exc.code}",
                correlation_id=correlation_id(),
                details={"message": exc.message[:500]},
            )
            raise ToolError(f"{exc.code}: {exc.message}") from exc
        c.metrics.tool_calls.labels("mcp", name, "ok").inc()
        await c.audit.record(
            actor=actor,
            action=f"mcp.{name}",
            resource=resource_id,
            outcome="ok",
            correlation_id=correlation_id(),
        )
        return result

    @server.tool(annotations=_READ)
    async def list_incidents(
        ctx: Context,
        status: IncidentStatus | None = None,
        limit: Annotated[int, Field(ge=1, le=100)] = 20,
    ) -> IncidentList:
        """List incidents, newest first, optionally filtered by status."""

        async def run(_: Principal, c: Container) -> IncidentList:
            items = await c.incidents.list(status=status, limit=limit)
            return IncidentList(items=items, limit=limit, offset=0)

        return await call(
            ctx,
            "list_incidents",
            action="incidents:read",
            resource_type="incident",
            resource_id="*",
            run=run,
        )

    @server.tool(annotations=_READ)
    async def get_incident(
        ctx: Context, incident_id: Annotated[str, Field(min_length=1, max_length=64)]
    ) -> Incident:
        """Fetch one incident with its alerts, diagnosis and linked remediation plans."""

        async def run(_: Principal, c: Container) -> Incident:
            return await c.incidents.get(incident_id)

        return await call(
            ctx,
            "get_incident",
            action="incidents:read",
            resource_type="incident",
            resource_id=incident_id,
            run=run,
        )

    @server.tool(annotations=_WRITE)
    async def diagnose_incident(
        ctx: Context, incident_id: Annotated[str, Field(min_length=1, max_length=64)]
    ) -> Incident:
        """Re-run the diagnosis playbook for an incident against fresh read-only evidence."""

        async def run(principal: Principal, c: Container) -> Incident:
            return await c.incidents.diagnose(incident_id, principal=principal)

        return await call(
            ctx,
            "diagnose_incident",
            action="alerts:diagnose",
            resource_type="incident",
            resource_id=incident_id,
            run=run,
        )

    @server.tool(annotations=_READ)
    async def analyze_terraform_plan(ctx: Context, plan: dict[str, Any]) -> PlanAnalysis:
        """Analyse `terraform show -json` output: destructive and stateful changes,
        disabled safety attributes, security-sensitive changes, drift and blast radius."""

        async def run(_: Principal, c: Container) -> PlanAnalysis:
            analysis = analyze_plan(plan)
            c.metrics.terraform_analyses.labels(analysis.risk.name.lower()).inc()
            return analysis

        return await call(
            ctx,
            "analyze_terraform_plan",
            action="terraform:analyze",
            resource_type="terraform:plan",
            resource_id="*",
            run=run,
        )

    @server.tool(annotations=_WRITE)
    async def propose_remediation(
        ctx: Context, action: ActionSpec, incident_id: str | None = None
    ) -> RemediationPlan:
        """Propose a remediation. The policy outcome decides whether it can run directly,
        needs human approval, or is denied; nothing changes until it is executed."""

        async def run(principal: Principal, c: Container) -> RemediationPlan:
            return await c.remediation.propose(action, principal=principal, incident_id=incident_id)

        return await call(
            ctx,
            "propose_remediation",
            action="remediation:propose",
            resource_type="remediation",
            resource_id=action.target.ref,
            run=run,
        )

    @server.tool(annotations=_READ)
    async def list_remediations(
        ctx: Context,
        status: PlanStatus | None = None,
        limit: Annotated[int, Field(ge=1, le=100)] = 20,
    ) -> PlanList:
        """List remediation plans, newest first, optionally filtered by status."""

        async def run(_: Principal, c: Container) -> PlanList:
            return PlanList(
                items=await c.remediation.list(status=status, limit=limit), limit=limit, offset=0
            )

        return await call(
            ctx,
            "list_remediations",
            action="remediation:read",
            resource_type="remediation",
            resource_id="*",
            run=run,
        )

    @server.tool(annotations=_WRITE)
    async def dry_run_remediation(
        ctx: Context, plan_id: Annotated[str, Field(min_length=1, max_length=64)]
    ) -> RemediationPlan:
        """Run a plan as a server-side dry run: admission and validation without persisting."""

        async def run(principal: Principal, c: Container) -> RemediationPlan:
            return await c.remediation.execute(plan_id, principal=principal, dry_run=True)

        return await call(
            ctx,
            "dry_run_remediation",
            action="remediation:dry-run",
            resource_type="remediation",
            resource_id=plan_id,
            run=run,
        )

    @server.tool(annotations=_LIVE)
    async def execute_remediation(
        ctx: Context, plan_id: Annotated[str, Field(min_length=1, max_length=64)]
    ) -> RemediationPlan:
        """Execute an allowed or approved plan live, with post-check and automatic rollback.
        Refused unless live execution is enabled and every required approval is recorded."""

        async def run(principal: Principal, c: Container) -> RemediationPlan:
            return await c.remediation.execute(plan_id, principal=principal, dry_run=False)

        return await call(
            ctx,
            "execute_remediation",
            action="remediation:execute",
            resource_type="remediation",
            resource_id=plan_id,
            run=run,
        )

    return server
