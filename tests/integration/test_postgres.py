"""Repository behaviour against a real PostgreSQL (CI service container).

Runs when HEAL_TEST_DATABASE_URL points at PostgreSQL, e.g.
postgresql+asyncpg://heal:heal@localhost:5432/heal
"""

from __future__ import annotations

import os
import uuid

import pytest

from self_healing_infrastructure_agents.domain.errors import ConflictError
from self_healing_infrastructure_agents.domain.models import Incident, IncidentStatus, PlanStatus
from self_healing_infrastructure_agents.infrastructure.database import (
    SqlIncidentRepository,
    SqlPlanRepository,
    create_schema,
    make_engine,
)
from tests.conftest import START
from tests.unit.test_models import make_alert, make_plan

URL = os.environ.get("HEAL_TEST_DATABASE_URL", "")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not URL.startswith("postgresql"), reason="PostgreSQL not configured"),
]


async def test_repositories_round_trip_and_concurrency() -> None:
    engine = make_engine(URL)
    await create_schema(engine)
    await create_schema(engine)  # idempotent
    incidents = SqlIncidentRepository(engine)
    plans = SqlPlanRepository(engine)
    fingerprint = f"am:pg-{uuid.uuid4().hex}"
    alert = make_alert(fingerprint=fingerprint)
    incident = Incident(
        fingerprint=fingerprint,
        title="pg",
        severity=alert.severity,
        status=IncidentStatus.OPEN,
        target=alert.target,
        alerts=(alert,),
        opened_at=START,
        updated_at=START,
    )
    await incidents.add(incident)
    assert await incidents.find_open(fingerprint) == incident
    duplicate = incident.model_copy(update={"id": uuid.uuid4().hex})
    with pytest.raises(ConflictError):
        await incidents.add(duplicate)  # one open incident per fingerprint
    resolved = incident.resolved("fixed", at=START)
    await incidents.update(resolved, expected_version=incident.version)
    assert await incidents.find_open(fingerprint) is None
    await incidents.add(duplicate)  # allowed again once the first is resolved
    with pytest.raises(ConflictError):
        await incidents.update(resolved, expected_version=incident.version)

    plan = make_plan()
    await plans.add(plan)
    assert await plans.get(plan.id) == plan
    assert any(p.id == plan.id for p in await plans.active_for_target(plan.action.target.ref))
    rejected = plan.model_copy(update={"status": PlanStatus.REJECTED, "version": 2})
    await plans.update(rejected, expected_version=1)
    assert all(p.id != plan.id for p in await plans.active_for_target(plan.action.target.ref))
    assert any(p.id == plan.id for p in await plans.list(status=PlanStatus.REJECTED))
    await engine.dispose()
