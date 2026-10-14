"""Read-only evidence collection from the cluster and the alert itself.

Collectors never mutate anything. A collector that fails records the error
and contributes no facts; hypotheses depending on those facts then simply
do not hold, so missing evidence can never trigger an action.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from self_healing_infrastructure_agents.diagnosis.playbooks import Collector
from self_healing_infrastructure_agents.domain.errors import HealingError
from self_healing_infrastructure_agents.domain.models import Alert, Evidence, Target, TargetKind
from self_healing_infrastructure_agents.domain.ports import (
    Clock,
    ClusterGateway,
    DeploymentState,
    NodeState,
    PodState,
)

_NUMBER = re.compile(r"^\s*(-?\d+(?:\.\d+)?)\s*(%)?\s*$")


def parse_ratio(raw: str | None) -> float | None:
    """'0.93' -> 0.93, '93%' -> 0.93, '93' -> 0.93 (percent), garbage -> None."""
    if raw is None:
        return None
    match = _NUMBER.match(raw)
    if match is None:
        return None
    value = float(match.group(1))
    if match.group(2) or value > 1.0:
        value /= 100.0
    return value if 0.0 <= value <= 10.0 else None


def parse_explicit_ratio(raw: str) -> float | None:
    try:
        value = float(raw)
    except ValueError:
        return None
    return value if 0.0 <= value <= 10.0 else None


def deployment_facts(deployment: DeploymentState) -> dict[str, Any]:
    replicas = deployment.replicas
    return {
        "replicas": replicas,
        "ready_replicas": deployment.ready_replicas,
        "updated_replicas": deployment.updated_replicas,
        "available_replicas": deployment.available_replicas,
        "ready_ratio": round(deployment.ready_replicas / replicas, 4) if replicas else 0.0,
        "revision": deployment.revision,
        "rollout_complete": deployment.rollout_complete,
        "progress_deadline_exceeded": deployment.progress_deadline_exceeded,
    }


def pod_facts(pods: Sequence[PodState], now: datetime) -> dict[str, Any]:
    ages = [(now - p.started_at).total_seconds() for p in pods if p.started_at is not None]
    return {
        "pod_count": len(pods),
        "ready_pods": sum(1 for p in pods if p.ready),
        "pending_pods": sum(1 for p in pods if p.phase == "Pending"),
        "restarting_pods": sum(1 for p in pods if p.restart_count > 0),
        "max_restart_count": max((p.restart_count for p in pods), default=0),
        "crashing_pods": sum(1 for p in pods if "CrashLoopBackOff" in p.waiting_reasons),
        "image_pull_errors": sum(
            1 for p in pods if {"ErrImagePull", "ImagePullBackOff"} & set(p.waiting_reasons)
        ),
        "oom_killed_pods": sum(
            1 for p in pods if any(t.reason == "OOMKilled" for t in p.last_terminations)
        ),
        "oldest_pod_age_seconds": int(max(ages, default=0)),
    }


def node_facts(node: NodeState, nodes: Sequence[NodeState]) -> dict[str, Any]:
    schedulable_ready = [
        n for n in nodes if n.ready and not n.unschedulable and not n.control_plane
    ]
    counted = node.ready and not node.unschedulable and not node.control_plane
    after = len(schedulable_ready) - (1 if counted else 0)
    return {
        "node_ready": node.ready,
        "node_unschedulable": node.unschedulable,
        "node_pressure": list(node.pressure),
        "node_pressure_count": len(node.pressure),
        "control_plane": node.control_plane,
        "ready_nodes": len(schedulable_ready),
        "ready_nodes_after": after,
        "ready_ratio_after": round(after / len(schedulable_ready), 4) if schedulable_ready else 0.0,
    }


def alert_facts(alert: Alert) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "alert_severity": alert.severity.value,
        "alert_name": alert.name,
    }
    # utilization_ratio is unambiguous (1.4 means 140%); value/current_value follow the
    # convention that numbers above 1 are percentages.
    explicit = alert.annotations.get("utilization_ratio")
    utilization = (
        parse_explicit_ratio(explicit)
        if explicit is not None
        else parse_ratio(alert.annotations.get("value") or alert.annotations.get("current_value"))
    )
    if utilization is not None:
        facts["utilization"] = utilization
    threshold = parse_ratio(alert.annotations.get("threshold"))
    if threshold is not None:
        facts["threshold"] = threshold
    return facts


_DEPLOYMENT_COLLECTORS = frozenset({"deployment", "pods", "rollout"})


def _applicable(name: Collector, target: Target) -> bool:
    if name == "alert":
        return True
    if name == "node":
        return target.kind is TargetKind.NODE
    return target.kind is TargetKind.DEPLOYMENT and name in _DEPLOYMENT_COLLECTORS


class EvidenceCollector:
    def __init__(self, cluster: ClusterGateway, clock: Clock) -> None:
        self._cluster = cluster
        self._clock = clock

    async def collect(
        self, collectors: Sequence[Collector], target: Target, alert: Alert
    ) -> Evidence:
        facts: dict[str, Any] = {}
        observations: list[str] = []
        errors: list[str] = []
        cache: dict[str, DeploymentState] = {}
        for name in collectors:
            if not _applicable(name, target):
                errors.append(f"{name}: not applicable to {target.kind.value} targets")
                continue
            try:
                facts.update(await self._collect(name, target, alert, cache))
            except HealingError as exc:
                errors.append(f"{name}: {exc.message}")
                continue
            observations.append(f"collected {name}")
        return Evidence(
            facts=facts,
            observations=tuple(observations),
            errors=tuple(errors),
            collected_at=self._clock.now(),
        )

    async def _deployment(
        self, target: Target, cache: dict[str, DeploymentState]
    ) -> DeploymentState:
        if "deployment" not in cache:
            cache["deployment"] = await self._cluster.get_deployment(
                target.namespace or "", target.name
            )
        return cache["deployment"]

    async def _collect(
        self, name: Collector, target: Target, alert: Alert, cache: dict[str, DeploymentState]
    ) -> dict[str, Any]:
        if name == "alert":
            return alert_facts(alert)
        if name == "node":
            node = await self._cluster.get_node(target.name)
            return node_facts(node, await self._cluster.list_nodes())
        deployment = await self._deployment(target, cache)
        if name == "pods":
            pods = await self._cluster.list_pods(deployment.namespace, deployment.selector)
            return pod_facts(pods, self._clock.now())
        if name == "rollout":
            return await self._rollout(deployment)
        return deployment_facts(deployment)

    async def _rollout(self, deployment: DeploymentState) -> dict[str, Any]:
        replicasets = await self._cluster.list_replicasets(
            deployment.namespace, deployment.selector
        )
        owned = [rs for rs in replicasets if rs.owner_uid in (None, deployment.uid)]
        current = next((rs for rs in owned if rs.revision == deployment.revision), None)
        previous = [rs for rs in owned if deployment.revision and rs.revision < deployment.revision]
        facts: dict[str, Any] = {
            "current_revision": deployment.revision,
            "previous_revision_available": bool(previous),
            "revision_count": len(owned),
        }
        if current is not None and current.created_at is not None:
            facts["rollout_age_seconds"] = int(
                (self._clock.now() - current.created_at).total_seconds()
            )
        return facts
