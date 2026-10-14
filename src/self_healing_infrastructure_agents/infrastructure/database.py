"""SQLAlchemy Core persistence. PostgreSQL in production; any async dialect works.

Aggregates are stored as JSON documents alongside the columns needed to
query them. Every update is a compare-and-set on ``version`` so two
replicas cannot both move a plan to ``executing`` or lose each other's
approvals. ``open_fingerprint`` is unique and NULL once an incident is
resolved, which makes "one open incident per alert fingerprint" a database
guarantee rather than an application convention.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from sqlalchemy import (
    Column,
    DateTime,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    insert,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from self_healing_infrastructure_agents.domain.errors import ConflictError, NotFoundError
from self_healing_infrastructure_agents.domain.models import (
    TERMINAL_PLAN_STATES,
    Incident,
    IncidentStatus,
    PlanStatus,
    RemediationPlan,
)

metadata = MetaData()

incidents = Table(
    "incidents",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("version", Integer, nullable=False),
    Column("fingerprint", String(200), nullable=False),
    Column("open_fingerprint", String(200), nullable=True, unique=True),
    Column("status", String(20), nullable=False),
    Column("target_ref", String(400), nullable=True),
    Column("document", Text, nullable=False),
    Column("opened_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Index("ix_incidents_status_opened", "status", "opened_at"),
    Index("ix_incidents_fingerprint", "fingerprint"),
)

plans = Table(
    "remediation_plans",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("version", Integer, nullable=False),
    Column("incident_id", String(64), nullable=True),
    Column("status", String(24), nullable=False),
    Column("target_ref", String(400), nullable=False),
    Column("digest", String(80), nullable=False),
    Column("document", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Index("ix_plans_status_created", "status", "created_at"),
    Index("ix_plans_target_status", "target_ref", "status"),
)

schema_version = Table(
    "schema_version",
    metadata,
    Column("version", Integer, primary_key=True),
)

SCHEMA_VERSION = 1


def make_engine(url: str) -> AsyncEngine:
    return create_async_engine(url, pool_pre_ping=True)


async def create_schema(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
        current = (await conn.execute(select(schema_version.c.version))).scalar()
        if current is None:
            await conn.execute(insert(schema_version).values(version=SCHEMA_VERSION))


async def _missing_or_stale(engine: AsyncEngine, kind: str, table: Table, key: str) -> None:
    """Explain a zero-row compare-and-set update."""
    async with engine.connect() as conn:
        exists = (await conn.execute(select(table.c.id).where(table.c.id == key))).first()
    if exists is None:
        raise NotFoundError(f"{kind} {key} not found")
    raise ConflictError(f"{kind} {key} was modified concurrently; retry")


def _incident_row(incident: Incident) -> dict[str, object]:
    return {
        "version": incident.version,
        "fingerprint": incident.fingerprint,
        "open_fingerprint": incident.fingerprint if incident.is_open else None,
        "status": incident.status.value,
        "target_ref": incident.target.ref if incident.target else None,
        "document": incident.model_dump_json(),
        "updated_at": incident.updated_at,
    }


class SqlIncidentRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, incident: Incident) -> None:
        try:
            async with self._engine.begin() as conn:
                await conn.execute(
                    insert(incidents).values(
                        id=incident.id, opened_at=incident.opened_at, **_incident_row(incident)
                    )
                )
        except IntegrityError as exc:
            raise ConflictError(f"an open incident exists for {incident.fingerprint}") from exc

    async def get(self, incident_id: str) -> Incident | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(incidents.c.document).where(incidents.c.id == incident_id)
                )
            ).first()
        return Incident.model_validate_json(row[0]) if row else None

    async def find_open(self, fingerprint: str) -> Incident | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(incidents.c.document).where(incidents.c.open_fingerprint == fingerprint)
                )
            ).first()
        return Incident.model_validate_json(row[0]) if row else None

    async def update(self, incident: Incident, *, expected_version: int) -> None:
        try:
            async with self._engine.begin() as conn:
                result = await conn.execute(
                    update(incidents)
                    .where(incidents.c.id == incident.id)
                    .where(incidents.c.version == expected_version)
                    .values(**_incident_row(incident))
                )
        except IntegrityError as exc:
            raise ConflictError(f"an open incident exists for {incident.fingerprint}") from exc
        if result.rowcount == 0:
            await _missing_or_stale(self._engine, "incident", incidents, incident.id)

    async def list(
        self, *, status: IncidentStatus | None = None, limit: int = 100, offset: int = 0
    ) -> Sequence[Incident]:
        query = (
            select(incidents.c.document)
            .order_by(incidents.c.opened_at.desc(), incidents.c.id)
            .limit(limit)
            .offset(offset)
        )
        if status is not None:
            query = query.where(incidents.c.status == status.value)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [Incident.model_validate_json(r[0]) for r in rows]


class SqlPlanRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    @staticmethod
    def _row(plan: RemediationPlan) -> dict[str, object]:
        return {
            "version": plan.version,
            "incident_id": plan.incident_id,
            "status": plan.status.value,
            "target_ref": plan.action.target.ref,
            "digest": plan.digest,
            "document": plan.model_dump_json(),
            "updated_at": plan.updated_at,
        }

    async def add(self, plan: RemediationPlan) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(plans).values(id=plan.id, created_at=plan.created_at, **self._row(plan))
            )

    async def get(self, plan_id: str) -> RemediationPlan | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(select(plans.c.document).where(plans.c.id == plan_id))
            ).first()
        return RemediationPlan.model_validate_json(row[0]) if row else None

    async def update(self, plan: RemediationPlan, *, expected_version: int) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(plans)
                .where(plans.c.id == plan.id)
                .where(plans.c.version == expected_version)
                .values(**self._row(plan))
            )
        if result.rowcount == 0:
            await _missing_or_stale(self._engine, "plan", plans, plan.id)

    async def list(
        self, *, status: PlanStatus | None = None, limit: int = 100, offset: int = 0
    ) -> Sequence[RemediationPlan]:
        query = (
            select(plans.c.document)
            .order_by(plans.c.created_at.desc(), plans.c.id)
            .limit(limit)
            .offset(offset)
        )
        if status is not None:
            query = query.where(plans.c.status == status.value)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [RemediationPlan.model_validate_json(r[0]) for r in rows]

    async def active_for_target(self, target_ref: str) -> Sequence[RemediationPlan]:
        terminal = [s.value for s in TERMINAL_PLAN_STATES]
        query = (
            select(plans.c.document)
            .where(plans.c.target_ref == target_ref)
            .where(plans.c.status.not_in(terminal))
        )
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [RemediationPlan.model_validate_json(r[0]) for r in rows]


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)
