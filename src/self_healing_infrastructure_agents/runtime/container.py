"""Dependency container built once per process from Settings (composition root)."""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import timedelta

import httpx
from agentic_core.audit import AuditLog, JsonlAuditSink
from agentic_core.models.factory import ProvidersConfig, build_providers
from agentic_core.models.router import ModelRouter
from agentic_core.observability import ModelTelemetryObserver
from agentic_core.policy import PolicyEngine, PolicySet
from agentic_core.security import ContentGuard
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.ext.asyncio import AsyncEngine

from self_healing_infrastructure_agents.application.incidents import IncidentService
from self_healing_infrastructure_agents.application.remediation import RemediationService
from self_healing_infrastructure_agents.config import Settings
from self_healing_infrastructure_agents.diagnosis.engine import DiagnosisEngine
from self_healing_infrastructure_agents.diagnosis.evidence import EvidenceCollector
from self_healing_infrastructure_agents.diagnosis.narrator import IncidentNarrator
from self_healing_infrastructure_agents.diagnosis.playbooks import PlaybookSet
from self_healing_infrastructure_agents.domain.models import (
    ExecutionMode,
    Principal,
    PrincipalKind,
)
from self_healing_infrastructure_agents.domain.ports import Clock, ClusterGateway, TerraformRunner
from self_healing_infrastructure_agents.governance.change_windows import ChangeCalendar
from self_healing_infrastructure_agents.governance.governor import RemediationGovernor
from self_healing_infrastructure_agents.infrastructure.database import (
    SqlIncidentRepository,
    SqlPlanRepository,
    SystemClock,
    create_schema,
    make_engine,
)
from self_healing_infrastructure_agents.integrations.identity_fabric import (
    FabricCredential,
    IdentityFabricClient,
)
from self_healing_infrastructure_agents.integrations.kubernetes import (
    KubernetesApiClient,
    file_token,
)
from self_healing_infrastructure_agents.integrations.terraform_cli import SubprocessTerraform
from self_healing_infrastructure_agents.observability.metrics import HealingMetrics
from self_healing_infrastructure_agents.remediation.executor import RemediationExecutor
from self_healing_infrastructure_agents.security.callers import (
    AgentAuthorizer,
    CallerResolver,
    FabricAgentAuthorizer,
    LocalAgentAuthorizer,
)
from self_healing_infrastructure_agents.security.jwks import KeyResolver, RemoteJwks
from self_healing_infrastructure_agents.security.operators import OperatorAuthenticator
from self_healing_infrastructure_agents.security.sns import SnsVerifier

Sleep = Callable[[float], Awaitable[None]]


@dataclass
class Container:
    settings: Settings
    incidents: IncidentService
    remediation: RemediationService
    callers: CallerResolver
    sns: SnsVerifier
    governor: RemediationGovernor
    playbooks: PlaybookSet
    audit: AuditLog
    metrics: HealingMetrics
    clock: Clock
    engine: AsyncEngine
    http: httpx.AsyncClient
    closers: list[Callable[[], Awaitable[None]]] = field(default_factory=list)

    async def aclose(self) -> None:
        for close in reversed(self.closers):
            await close()
        await self.http.aclose()
        await self.engine.dispose()


def _audit_signer(settings: Settings) -> tuple[Ed25519PrivateKey, str]:
    if settings.audit_key_file is None:
        return Ed25519PrivateKey.generate(), "audit-ephemeral"
    key = serialization.load_pem_private_key(settings.audit_key_file.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("audit key must be Ed25519")
    return key, settings.audit_key_file.stem


def _kubernetes(settings: Settings) -> tuple[KubernetesApiClient, httpx.AsyncClient]:
    verify: ssl.SSLContext | bool = True
    if settings.kube_ca_file.is_file():
        verify = ssl.create_default_context(cafile=str(settings.kube_ca_file))
    client = httpx.AsyncClient(
        base_url=settings.kube_api_url, verify=verify, timeout=httpx.Timeout(10.0)
    )
    return KubernetesApiClient(client, token=file_token(settings.kube_token_file)), client


def _narrator(
    settings: Settings, transport: httpx.AsyncBaseTransport | None
) -> tuple[IncidentNarrator | None, ModelRouter | None]:
    if settings.providers_file is None:
        return None, None
    config = ProvidersConfig.from_file(settings.providers_file)
    router = ModelRouter(
        build_providers(config, transport=transport), observers=[ModelTelemetryObserver()]
    )
    return IncidentNarrator(router, ContentGuard()), router


async def build_container(
    settings: Settings,
    *,
    cluster: ClusterGateway | None = None,
    terraform: TerraformRunner | None = None,
    operator_resolver: KeyResolver | None = None,
    agent_resolver: KeyResolver | None = None,
    clock: Clock | None = None,
    sleep: Sleep = asyncio.sleep,
    http: httpx.AsyncClient | None = None,
    model_transport: httpx.AsyncBaseTransport | None = None,
) -> Container:
    clock = clock or SystemClock()
    http = http or httpx.AsyncClient(timeout=httpx.Timeout(10.0))
    closers: list[Callable[[], Awaitable[None]]] = []
    if cluster is None:
        kube, kube_http = _kubernetes(settings)
        cluster = kube
        closers.append(kube_http.aclose)
    terraform = terraform or SubprocessTerraform(
        settings.terraform_root,
        command=(settings.terraform_binary,),
        timeout_s=settings.terraform_timeout_seconds,
    )

    engine = make_engine(settings.database_url)
    await create_schema(engine)

    signer, key_id = _audit_signer(settings)
    audit = AuditLog(JsonlAuditSink(settings.audit_log_path), signer, key_id=key_id)
    metrics = HealingMetrics()

    governor = RemediationGovernor(
        PolicyEngine(PolicySet.from_file(settings.policy_file)),
        ChangeCalendar.from_file(settings.change_calendar_file),
        protected_namespaces=frozenset(settings.protected_namespaces),
    )
    playbooks = PlaybookSet.from_file(settings.playbooks_file)
    narrator, router = _narrator(settings, model_transport)
    if router is not None:
        closers.append(router.aclose)

    operators = OperatorAuthenticator(
        operator_resolver or RemoteJwks(settings.operator_jwks_url, client=http),
        issuer=settings.operator_issuer,
        audience=settings.operator_audience,
        clock=clock,
        roles_claim=settings.operator_roles_claim,
    )
    fabric: tuple[IdentityFabricClient, FabricCredential] | None = None
    agents: AgentAuthorizer
    if settings.fabric_url:
        client = IdentityFabricClient(settings.fabric_url, http)
        fabric = (
            client,
            FabricCredential(
                client,
                agent_id=settings.agent_id,
                workload_token=file_token(settings.workload_token_file),
                scopes=frozenset(settings.agent_scopes),
                clock=clock,
            ),
        )
        agents = FabricAgentAuthorizer(client, clock=clock)
    else:
        if settings.agent_issuer is None or settings.agent_jwks_url is None:
            raise ValueError("agent verification is not configured")  # pragma: no cover
        agents = LocalAgentAuthorizer(
            agent_resolver or RemoteJwks(settings.agent_jwks_url, client=http),
            PolicyEngine(PolicySet.from_file(settings.access_policy_file)),
            issuer=settings.agent_issuer,
            audience=settings.agent_audience,
            clock=clock,
        )

    plans = SqlPlanRepository(engine)
    incidents_repo = SqlIncidentRepository(engine)
    remediation = RemediationService(
        plans=plans,
        incidents=incidents_repo,
        governor=governor,
        executor=RemediationExecutor(
            cluster,
            terraform,
            clock,
            sleep=sleep,
            rollout_timeout_s=settings.rollout_timeout_seconds,
            poll_interval_s=settings.poll_interval_seconds,
        ),
        cluster=cluster,
        terraform=terraform,
        audit=audit,
        clock=clock,
        metrics=metrics,
        live_execution_enabled=settings.execution_mode is ExecutionMode.LIVE,
        plan_ttl=timedelta(seconds=settings.plan_ttl_seconds),
        fabric=fabric,
    )
    incidents = IncidentService(
        incidents=incidents_repo,
        engine=DiagnosisEngine(playbooks, EvidenceCollector(cluster, clock), clock, narrator),
        remediation=remediation,
        audit=audit,
        clock=clock,
        metrics=metrics,
        agent=Principal(
            subject=settings.agent_id,
            kind=PrincipalKind.AGENT,
            scopes=frozenset(settings.agent_scopes),
        ),
        auto_propose=settings.auto_propose,
        auto_execute=settings.auto_execute,
    )
    return Container(
        settings=settings,
        incidents=incidents,
        remediation=remediation,
        callers=CallerResolver(
            operators=operators, operator_issuer=settings.operator_issuer, agents=agents
        ),
        sns=SnsVerifier(allowed_topics=frozenset(settings.sns_topic_arns), http=http, clock=clock),
        governor=governor,
        playbooks=playbooks,
        audit=audit,
        metrics=metrics,
        clock=clock,
        engine=engine,
        http=http,
        closers=closers,
    )
