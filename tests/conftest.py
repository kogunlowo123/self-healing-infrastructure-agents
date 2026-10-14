"""Shared fixtures: fake clock, identity providers, Kubernetes cluster and Terraform runner,
a container wired to SQLite, and an ASGI test client.

Fakes implement the same ports as the production adapters (ClusterGateway,
TerraformRunner, KeyResolver), so services run their real logic against them.
"""

from __future__ import annotations

import json
import os
from collections import deque
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from self_healing_infrastructure_agents.api.app import create_app
from self_healing_infrastructure_agents.config import Settings
from self_healing_infrastructure_agents.domain.errors import (
    ConflictError,
    IntegrationUnavailableError,
    TargetNotFoundError,
)
from self_healing_infrastructure_agents.domain.models import ExecutionMode
from self_healing_infrastructure_agents.domain.ports import (
    CommandResult,
    DeploymentState,
    NodeState,
    PodState,
    ReplicaSetState,
)
from self_healing_infrastructure_agents.runtime.container import Container, build_container
from self_healing_infrastructure_agents.security.jwks import StaticJwks

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
OPERATOR_ISSUER = "https://login.corp.test/tenant"
OPERATOR_AUDIENCE = "self-healing-agents"
AGENT_ISSUER = "https://identity.corp.test"
AGENT_AUDIENCE = "agent-platform"
AGENT_ID = "spiffe://agents.corp.test/agent/platform/self-healer"
PUBLIC_URL = "https://heal.corp.test"
TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:infra-alarms"
ALERTMANAGER_TOKEN = "am-webhook-credential-for-tests-0123456789"
# Wednesday 14:00 UTC = 10:00 America/New_York: inside the production change window.
START = datetime(2026, 10, 14, 14, 0, tzinfo=UTC)


def load(relative: str) -> Any:
    return json.loads((FIXTURES / relative).read_text(encoding="utf-8"))


@dataclass
class FakeClock:
    current: datetime = START

    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)

    async def sleep(self, seconds: float) -> None:
        self.advance(seconds)


@dataclass
class FakeIdp:
    """ES256 OIDC issuer; tokens are minted against the fake clock."""

    issuer: str
    clock: FakeClock
    kid: str = "k1"
    key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )

    def jwks(self) -> dict[str, Any]:
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        jwk.update({"kid": self.kid, "alg": "ES256", "use": "sig"})
        return {"keys": [jwk]}

    def mint(self, *, sub: str, aud: str, ttl: int = 600, **extra: Any) -> str:
        now = int(self.clock.now().timestamp())
        claims = {"iss": self.issuer, "sub": sub, "aud": aud, "iat": now, "exp": now + ttl}
        claims.update(extra)
        return jwt.encode(claims, self.key, algorithm="ES256", headers={"kid": self.kid})


# ------------------------------------------------------------------ cluster


def deployment(
    name: str = "checkout",
    namespace: str = "payments",
    *,
    replicas: int = 4,
    ready: int | None = None,
    revision: int = 7,
    generation: int = 12,
    deadline_exceeded: bool = False,
) -> DeploymentState:
    ready = replicas if ready is None else ready
    return DeploymentState(
        namespace=namespace,
        name=name,
        uid=f"uid-{name}",
        resource_version="1000",
        generation=generation,
        observed_generation=generation,
        replicas=replicas,
        ready_replicas=ready,
        updated_replicas=ready,
        available_replicas=ready,
        revision=revision,
        selector={"app.kubernetes.io/name": name},
        template={
            "metadata": {"labels": {"app.kubernetes.io/name": name}},
            "spec": {
                "containers": [{"name": name, "image": f"registry.corp.test/{name}:r{revision}"}]
            },
        },
        progress_deadline_exceeded=deadline_exceeded,
        created_at=START - timedelta(days=200),
    )


def replicaset(name: str, revision: int, *, owner: str, age: timedelta) -> ReplicaSetState:
    return ReplicaSetState(
        name=f"{name}-rs{revision}",
        revision=revision,
        owner_uid=owner,
        template={
            "metadata": {
                "labels": {"app.kubernetes.io/name": name, "pod-template-hash": f"h{revision}"}
            },
            "spec": {
                "containers": [{"name": name, "image": f"registry.corp.test/{name}:r{revision}"}]
            },
        },
        created_at=START - age,
    )


def node(name: str, *, ready: bool = True, unschedulable: bool = False, **extra: Any) -> NodeState:
    return NodeState(
        name=name,
        resource_version="500",
        ready=ready,
        unschedulable=unschedulable,
        **extra,
    )


@dataclass
class FakeCluster:
    """In-memory ClusterGateway.

    ``outcomes`` decides how each live mutation of a deployment settles:
    ``complete`` (rollout finishes), ``stuck`` (pods never become ready) or
    ``deadline`` (ProgressDeadlineExceeded). Outcomes are consumed in order;
    the last one repeats.
    """

    deployments: dict[tuple[str, str], DeploymentState] = field(default_factory=dict)
    replicasets: dict[str, list[ReplicaSetState]] = field(default_factory=dict)
    pods: dict[str, list[PodState]] = field(default_factory=dict)
    nodes: dict[str, NodeState] = field(default_factory=dict)
    outcomes: deque[str] = field(default_factory=lambda: deque(["complete"]))
    node_outcomes: deque[str] = field(default_factory=lambda: deque(["complete"]))
    calls: list[tuple[Any, ...]] = field(default_factory=list)
    unavailable: set[str] = field(default_factory=set)

    def _check(self, method: str) -> None:
        if method in self.unavailable or "*" in self.unavailable:
            raise IntegrationUnavailableError(f"Kubernetes API unreachable during {method}")

    def _outcome(self, queue: deque[str]) -> str:
        return queue.popleft() if len(queue) > 1 else queue[0]

    def add(self, state: DeploymentState) -> None:
        self.deployments[(state.namespace, state.name)] = state

    async def get_deployment(self, namespace: str, name: str) -> DeploymentState:
        self._check("get_deployment")
        try:
            return self.deployments[(namespace, name)]
        except KeyError as exc:
            raise TargetNotFoundError(f"deployment {namespace}/{name} not found") from exc

    async def list_replicasets(
        self, namespace: str, selector: dict[str, str]
    ) -> list[ReplicaSetState]:
        self._check("list_replicasets")
        return list(self.replicasets.get(namespace, []))

    async def list_pods(self, namespace: str, selector: dict[str, str]) -> list[PodState]:
        self._check("list_pods")
        return list(self.pods.get(namespace, []))

    async def get_node(self, name: str) -> NodeState:
        self._check("get_node")
        try:
            return self.nodes[name]
        except KeyError as exc:
            raise TargetNotFoundError(f"node {name} not found") from exc

    async def list_nodes(self) -> list[NodeState]:
        self._check("list_nodes")
        return list(self.nodes.values())

    def _settle(self, before: DeploymentState, **changes: Any) -> DeploymentState:
        outcome = self._outcome(self.outcomes)
        replicas = changes.get("replicas", before.replicas)
        ready = replicas if outcome == "complete" else max(0, replicas - 1)
        generation = before.generation + 1
        return before.model_copy(
            update={
                **changes,
                "generation": generation,
                "observed_generation": generation,
                "ready_replicas": ready,
                "updated_replicas": ready,
                "available_replicas": ready,
                "resource_version": str(int(before.resource_version) + 1),
                "progress_deadline_exceeded": outcome == "deadline",
            }
        )

    async def restart_deployment(
        self, namespace: str, name: str, *, at: datetime, dry_run: bool
    ) -> DeploymentState:
        self._check("restart_deployment")
        self.calls.append(("restart", namespace, name, dry_run))
        current = await self.get_deployment(namespace, name)
        template = json.loads(json.dumps(current.template))
        template.setdefault("metadata", {}).setdefault("annotations", {})[
            "kubectl.kubernetes.io/restartedAt"
        ] = at.isoformat()
        if dry_run:
            return current.model_copy(update={"template": template})
        updated = self._settle(current, template=template, revision=(current.revision or 0) + 1)
        self.add(updated)
        return updated

    async def scale_deployment(
        self, namespace: str, name: str, replicas: int, *, dry_run: bool
    ) -> DeploymentState:
        self._check("scale_deployment")
        self.calls.append(("scale", namespace, name, replicas, dry_run))
        current = await self.get_deployment(namespace, name)
        if dry_run:
            return current.model_copy(update={"replicas": replicas})
        updated = self._settle(current, replicas=replicas)
        self.add(updated)
        return updated

    async def replace_pod_template(
        self,
        namespace: str,
        name: str,
        template: dict[str, Any],
        *,
        resource_version: str,
        dry_run: bool,
    ) -> DeploymentState:
        self._check("replace_pod_template")
        self.calls.append(("template", namespace, name, dry_run))
        current = await self.get_deployment(namespace, name)
        if resource_version != current.resource_version:
            raise ConflictError("resourceVersion test failed")
        if dry_run:
            return current.model_copy(update={"template": template})
        updated = self._settle(current, template=template, revision=(current.revision or 0) + 1)
        self.add(updated)
        return updated

    async def set_unschedulable(
        self, name: str, unschedulable: bool, *, dry_run: bool
    ) -> NodeState:
        self._check("set_unschedulable")
        self.calls.append(("cordon" if unschedulable else "uncordon", name, dry_run))
        current = await self.get_node(name)
        wanted = current.model_copy(update={"unschedulable": unschedulable})
        if dry_run:
            return wanted
        if self._outcome(self.node_outcomes) == "ignored":
            return current  # e.g. an admission webhook silently reverts the change
        self.nodes[name] = wanted
        return wanted


@pytest.fixture
def cluster() -> FakeCluster:
    fake = FakeCluster()
    fake.add(deployment())
    fake.add(deployment("ledger", "finance", replicas=3))
    fake.add(deployment("dns", "kube-system", replicas=2))
    for n in ("node-a", "node-b", "node-c", "node-d"):
        fake.nodes[n] = node(n)
    return fake


# ---------------------------------------------------------------- terraform


@dataclass
class FakeTerraform:
    """In-memory TerraformRunner holding plan documents per (stack, plan file)."""

    plans: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    apply_exit: deque[int] = field(default_factory=lambda: deque([0]))
    converged_exit: deque[int] = field(default_factory=lambda: deque([0]))
    plan_exit: int = 0
    next_plan: dict[str, Any] | None = None
    calls: list[tuple[str, ...]] = field(default_factory=list)

    @staticmethod
    def _next(queue: deque[int]) -> int:
        return queue.popleft() if len(queue) > 1 else queue[0]

    def _result(self, args: tuple[str, ...], code: int) -> CommandResult:
        return CommandResult(
            args=args, exit_code=code, stdout_tail="", stderr_tail="", duration_s=0.01
        )

    async def show_plan(self, stack: str, plan_file: str) -> dict[str, Any]:
        self.calls.append(("show", stack, plan_file))
        try:
            return self.plans[(stack, plan_file)]
        except KeyError as exc:
            from self_healing_infrastructure_agents.domain.errors import HealingError

            raise HealingError(f"plan file {plan_file!r} not found in stack {stack!r}") from exc

    async def plan(self, stack: str, out_file: str) -> CommandResult:
        self.calls.append(("plan", stack, out_file))
        if self.plan_exit == 0 and self.next_plan is not None:
            self.plans[(stack, out_file)] = self.next_plan
        return self._result(("plan",), self.plan_exit)

    async def apply(self, stack: str, plan_file: str) -> CommandResult:
        self.calls.append(("apply", stack, plan_file))
        return self._result(("apply", plan_file), self._next(self.apply_exit))

    async def check_converged(self, stack: str) -> CommandResult:
        self.calls.append(("converged", stack))
        return self._result(("plan", "-detailed-exitcode"), self._next(self.converged_exit))


@pytest.fixture
def terraform() -> FakeTerraform:
    fake = FakeTerraform()
    fake.plans[("rds/orders", "resize.tfplan")] = load("terraform/aws-rds-storage-resize.plan.json")
    fake.plans[("rds/orders", "replace.tfplan")] = load(
        "terraform/aws-rds-replace-and-bucket-delete.plan.json"
    )
    fake.plans[("rds/orders", "unsafe.tfplan")] = load(
        "terraform/aws-rds-protection-disabled.plan.json"
    )
    return fake


# ------------------------------------------------------------------ settings


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def operator_idp(clock: FakeClock) -> FakeIdp:
    return FakeIdp(OPERATOR_ISSUER, clock, kid="op-1")


@pytest.fixture
def agent_idp(clock: FakeClock) -> FakeIdp:
    return FakeIdp(AGENT_ISSUER, clock, kid="fabric-2026-10")


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    db = os.environ.get("HEAL_TEST_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'heal.db'}")
    values: dict[str, Any] = {
        "environment": "test",
        "public_url": PUBLIC_URL,
        "database_url": db,
        "default_alert_environment": "staging",
        "audit_log_path": tmp_path / "audit.jsonl",
        "dev_ephemeral_keys": True,
        "execution_mode": ExecutionMode.DRY_RUN,
        "operator_issuer": OPERATOR_ISSUER,
        "operator_audience": OPERATOR_AUDIENCE,
        "operator_jwks_url": "https://login.corp.test/jwks",
        "agent_id": AGENT_ID,
        "agent_issuer": AGENT_ISSUER,
        "agent_jwks_url": "https://identity.corp.test/.well-known/jwks.json",
        "agent_audience": AGENT_AUDIENCE,
        "alertmanager_token": ALERTMANAGER_TOKEN,
        "sns_topic_arns": [TOPIC_ARN],
        "terraform_root": tmp_path / "stacks",
        "policy_file": ROOT / "policies" / "remediation.yaml",
        "access_policy_file": ROOT / "policies" / "agent-access.yaml",
        "playbooks_file": ROOT / "policies" / "diagnosis-playbooks.yaml",
        "change_calendar_file": ROOT / "policies" / "change-windows.yaml",
        "kube_ca_file": tmp_path / "missing-ca.crt",
        "kube_token_file": tmp_path / "missing-token",
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path)


async def wired(
    settings: Settings,
    *,
    cluster: FakeCluster,
    terraform: FakeTerraform,
    clock: FakeClock,
    operator_idp: FakeIdp,
    agent_idp: FakeIdp,
    **extra: Any,
) -> Container:
    return await build_container(
        settings,
        cluster=cluster,
        terraform=terraform,
        operator_resolver=StaticJwks(operator_idp.jwks()),
        agent_resolver=StaticJwks(agent_idp.jwks()),
        clock=clock,
        sleep=clock.sleep,
        **extra,
    )


@pytest.fixture
async def container(
    settings: Settings,
    cluster: FakeCluster,
    terraform: FakeTerraform,
    clock: FakeClock,
    operator_idp: FakeIdp,
    agent_idp: FakeIdp,
) -> AsyncIterator[Container]:
    built = await wired(
        settings,
        cluster=cluster,
        terraform=terraform,
        clock=clock,
        operator_idp=operator_idp,
        agent_idp=agent_idp,
    )
    yield built
    await built.aclose()


# ------------------------------------------------------------------- callers


def operator_headers(idp: FakeIdp, *roles: str, sub: str = "alice@corp.test") -> dict[str, str]:
    token = idp.mint(sub=sub, aud=OPERATOR_AUDIENCE, roles=list(roles))
    return {"Authorization": f"Bearer {token}"}


def agent_headers(
    idp: FakeIdp,
    *scopes: str,
    sub: str = "spiffe://agents.corp.test/agent/sre/triage",
    **extra: Any,
) -> dict[str, str]:
    token = idp.mint(sub=sub, aud=AGENT_AUDIENCE, scope=" ".join(scopes), **extra)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client(
    settings: Settings,
    cluster: FakeCluster,
    terraform: FakeTerraform,
    clock: FakeClock,
    operator_idp: FakeIdp,
    agent_idp: FakeIdp,
) -> Iterator[TestClient]:
    """App whose container is built inside the app's own event loop by its lifespan."""

    async def factory() -> Container:
        return await wired(
            settings,
            cluster=cluster,
            terraform=terraform,
            clock=clock,
            operator_idp=operator_idp,
            agent_idp=agent_idp,
        )

    with TestClient(create_app(factory), base_url=PUBLIC_URL) as test_client:
        yield test_client
