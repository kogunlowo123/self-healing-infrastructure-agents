"""Derive the remediation target from alert labels.

Label conventions follow kube-state-metrics, node-exporter and the
kube-prometheus mixin: ``namespace`` + ``deployment`` (or a pod name whose
ReplicaSet hash can be stripped), ``node`` (or ``instance`` for
node-exporter), ``cluster`` and ``environment``/``env``. Labels that do not
form a valid Kubernetes object reference yield no target rather than a
guessed one.
"""

from __future__ import annotations

import re

from pydantic import ValidationError

from self_healing_infrastructure_agents.domain.models import Target, TargetKind

# <deployment>-<pod-template-hash>-<random suffix>
_POD_OF_DEPLOYMENT = re.compile(
    r"^(?P<name>[a-z0-9]([-a-z0-9]*[a-z0-9])?)-[a-z0-9]{6,10}-[a-z0-9]{5}$"
)
_NODE_EXPORTER_JOBS = frozenset({"node-exporter", "node", "prometheus-node-exporter"})


def deployment_from_pod(pod: str) -> str | None:
    match = _POD_OF_DEPLOYMENT.fullmatch(pod)
    return match.group("name") if match else None


def environment_of(labels: dict[str, str], default: str) -> str:
    return labels.get("environment") or labels.get("env") or default


def _target(**fields: str | TargetKind | None) -> Target | None:
    try:
        return Target.model_validate(fields)
    except ValidationError:
        return None


def target_from_labels(labels: dict[str, str], *, default_environment: str) -> Target | None:
    environment = environment_of(labels, default_environment)
    cluster = labels.get("cluster") or None

    namespace = labels.get("namespace")
    deployment = labels.get("deployment") or labels.get("horizontalpodautoscaler")
    if deployment is None and labels.get("pod"):
        deployment = deployment_from_pod(labels["pod"])
    if namespace and deployment:
        found = _target(
            kind=TargetKind.DEPLOYMENT,
            name=deployment,
            namespace=namespace,
            cluster=cluster,
            environment=environment,
        )
        if found is not None:
            return found

    node = labels.get("node")
    if node is None and labels.get("job") in _NODE_EXPORTER_JOBS and labels.get("instance"):
        node = labels["instance"].rsplit(":", 1)[0]
    if node:
        return _target(kind=TargetKind.NODE, name=node, cluster=cluster, environment=environment)
    return None
