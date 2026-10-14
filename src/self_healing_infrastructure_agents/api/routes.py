"""HTTP routes for incidents, Terraform analysis, remediation and operations.

Every route authorizes its caller through the CallerResolver: operators by
enterprise OIDC role, agents by the identity fabric (or the local access
policy). Approvals are restricted to human operators.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from self_healing_infrastructure_agents.analysis.terraform_plan import analyze_plan
from self_healing_infrastructure_agents.api.deps import container
from self_healing_infrastructure_agents.api.schemas import (
    AnalyzePlanRequest,
    ApprovalRequest,
    ExecuteRequest,
    IncidentList,
    PlanList,
    ProposeRemediation,
)
from self_healing_infrastructure_agents.domain.models import (
    Incident,
    IncidentStatus,
    PlanAnalysis,
    PlanStatus,
    RemediationPlan,
)
from self_healing_infrastructure_agents.runtime.container import Container

router = APIRouter()
Deps = Annotated[Container, Depends(container)]
Authorization = Annotated[str | None, Header()]
Limit = Annotated[int, Query(ge=1, le=500)]
Offset = Annotated[int, Query(ge=0, le=100_000)]


# ------------------------------------------------------------------ incidents


@router.get("/v1/incidents", tags=["incidents"])
async def list_incidents(
    c: Deps,
    authorization: Authorization = None,
    status: IncidentStatus | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> IncidentList:
    await c.callers.resolve(authorization, action="incidents:read", resource_type="incident")
    items = await c.incidents.list(status=status, limit=limit, offset=offset)
    return IncidentList(items=items, limit=limit, offset=offset)


@router.get("/v1/incidents/{incident_id}", tags=["incidents"])
async def get_incident(incident_id: str, c: Deps, authorization: Authorization = None) -> Incident:
    await c.callers.resolve(
        authorization, action="incidents:read", resource_type="incident", resource_id=incident_id
    )
    return await c.incidents.get(incident_id)


@router.post("/v1/incidents/{incident_id}/diagnose", tags=["incidents"])
async def diagnose_incident(
    incident_id: str, c: Deps, authorization: Authorization = None
) -> Incident:
    principal = await c.callers.resolve(
        authorization, action="alerts:diagnose", resource_type="incident", resource_id=incident_id
    )
    return await c.incidents.diagnose(incident_id, principal=principal)


# ------------------------------------------------------------------ terraform


@router.post("/v1/terraform/analyze", tags=["terraform"])
async def analyze_terraform_plan(
    body: AnalyzePlanRequest, c: Deps, authorization: Authorization = None
) -> PlanAnalysis:
    await c.callers.resolve(
        authorization, action="terraform:analyze", resource_type="terraform:plan"
    )
    analysis = analyze_plan(body.plan)
    c.metrics.terraform_analyses.labels(analysis.risk.name.lower()).inc()
    return analysis


# ---------------------------------------------------------------- remediation


@router.post("/v1/remediations", status_code=201, tags=["remediation"])
async def propose_remediation(
    body: ProposeRemediation, c: Deps, authorization: Authorization = None
) -> RemediationPlan:
    principal = await c.callers.resolve(
        authorization,
        action="remediation:propose",
        resource_type="remediation",
        resource_id=body.action.target.ref,
    )
    return await c.remediation.propose(
        body.action, principal=principal, incident_id=body.incident_id
    )


@router.get("/v1/remediations", tags=["remediation"])
async def list_remediations(
    c: Deps,
    authorization: Authorization = None,
    status: PlanStatus | None = None,
    limit: Limit = 100,
    offset: Offset = 0,
) -> PlanList:
    await c.callers.resolve(authorization, action="remediation:read", resource_type="remediation")
    items = await c.remediation.list(status=status, limit=limit, offset=offset)
    return PlanList(items=items, limit=limit, offset=offset)


@router.get("/v1/remediations/{plan_id}", tags=["remediation"])
async def get_remediation(
    plan_id: str, c: Deps, authorization: Authorization = None
) -> RemediationPlan:
    await c.callers.resolve(
        authorization, action="remediation:read", resource_type="remediation", resource_id=plan_id
    )
    return await c.remediation.get(plan_id)


@router.post("/v1/remediations/{plan_id}/decision", tags=["remediation"])
async def decide_remediation(
    plan_id: str, body: ApprovalRequest, c: Deps, authorization: Authorization = None
) -> RemediationPlan:
    """Human approval or rejection. Agents cannot approve; requesters cannot approve their own."""
    approver = await c.callers.operator(authorization, scope="remediation:approve")
    return await c.remediation.decide(
        plan_id,
        approver=approver,
        decision=body.decision,
        plan_digest=body.plan_digest,
        comment=body.comment,
    )


@router.post("/v1/remediations/{plan_id}/execute", tags=["remediation"])
async def execute_remediation(
    plan_id: str, body: ExecuteRequest, c: Deps, authorization: Authorization = None
) -> RemediationPlan:
    principal = await c.callers.resolve(
        authorization,
        action="remediation:dry-run" if body.dry_run else "remediation:execute",
        resource_type="remediation",
        resource_id=plan_id,
    )
    return await c.remediation.execute(plan_id, principal=principal, dry_run=body.dry_run)


# ----------------------------------------------------------------- operations


@router.get("/healthz", tags=["operations"], include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", tags=["operations"], include_in_schema=False)
async def readyz(c: Deps, response: Response) -> dict[str, str]:
    try:
        async with c.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        response.status_code = 503
        return {"status": "database unavailable"}
    return {"status": "ready", "execution_mode": c.settings.execution_mode.value}


@router.get("/metrics", tags=["operations"], include_in_schema=False)
async def metrics(c: Deps) -> Response:
    return Response(generate_latest(c.metrics.registry), media_type=CONTENT_TYPE_LATEST)
