"""Kubernetes API adapter over HTTPS.

Speaks the API server's REST interface directly (apps/v1 Deployments and
ReplicaSets, core/v1 Pods and Nodes) so every request and response shape is
explicit and testable against recorded wire documents. In-cluster it
authenticates with the pod's projected service-account token, re-read on
every request because the kubelet rotates it, and verifies the API server
against the mounted cluster CA.

Mutations:

* restart     strategic-merge patch of ``kubectl.kubernetes.io/restartedAt``
              on the pod template (what ``kubectl rollout restart`` does);
* scale       merge patch of the ``scale`` subresource;
* template    JSON patch with a ``test`` on ``metadata.resourceVersion`` so a
              concurrent writer makes the patch fail instead of being lost;
              used for rollout undo and to roll back a restart;
* cordon      strategic-merge patch of ``spec.unschedulable``.

``dry_run=True`` adds ``dryRun=All``: the API server runs admission and
validation and returns the would-be object without persisting it.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from self_healing_infrastructure_agents.domain.errors import (
    ConflictError,
    ForbiddenError,
    IntegrationError,
    IntegrationUnavailableError,
    TargetNotFoundError,
)
from self_healing_infrastructure_agents.domain.ports import (
    ContainerTermination,
    DeploymentState,
    NodeState,
    PodState,
    ReplicaSetState,
)

FIELD_MANAGER = "self-healing-infrastructure-agents"
RESTARTED_AT = "kubectl.kubernetes.io/restartedAt"
REVISION = "deployment.kubernetes.io/revision"
STRATEGIC = "application/strategic-merge-patch+json"
MERGE = "application/merge-patch+json"
JSON_PATCH = "application/json-patch+json"

TokenProvider = Callable[[], str]


def file_token(path: Path) -> TokenProvider:
    """Read the projected service-account token on every call (it rotates)."""

    def read() -> str:
        return path.read_text(encoding="utf-8").strip()

    return read


def _ts(value: Any) -> datetime | None:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None


def _selector(labels: dict[str, str]) -> str:
    return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))


def _revision(metadata: dict[str, Any]) -> int | None:
    raw = (metadata.get("annotations") or {}).get(REVISION)
    try:
        return int(raw) if raw is not None else None
    except ValueError:
        return None


def deployment_state(document: dict[str, Any]) -> DeploymentState:
    metadata = document.get("metadata", {})
    spec = document.get("spec", {})
    status = document.get("status", {})
    conditions = status.get("conditions", []) or []
    return DeploymentState(
        namespace=metadata["namespace"],
        name=metadata["name"],
        uid=metadata.get("uid", ""),
        resource_version=metadata.get("resourceVersion", ""),
        generation=int(metadata.get("generation", 0)),
        observed_generation=int(status.get("observedGeneration", 0)),
        replicas=int(spec.get("replicas", 1)),
        ready_replicas=int(status.get("readyReplicas", 0)),
        updated_replicas=int(status.get("updatedReplicas", 0)),
        available_replicas=int(status.get("availableReplicas", 0)),
        revision=_revision(metadata),
        selector=dict((spec.get("selector") or {}).get("matchLabels") or {}),
        template=spec.get("template", {}),
        progress_deadline_exceeded=any(
            c.get("type") == "Progressing" and c.get("reason") == "ProgressDeadlineExceeded"
            for c in conditions
        ),
        created_at=_ts(metadata.get("creationTimestamp")),
    )


def replicaset_state(document: dict[str, Any]) -> ReplicaSetState:
    metadata = document.get("metadata", {})
    owners = metadata.get("ownerReferences", []) or []
    owner = next((o.get("uid") for o in owners if o.get("kind") == "Deployment"), None)
    return ReplicaSetState(
        name=metadata["name"],
        revision=_revision(metadata) or 0,
        owner_uid=owner,
        template=(document.get("spec") or {}).get("template", {}),
        created_at=_ts(metadata.get("creationTimestamp")),
    )


def pod_state(document: dict[str, Any]) -> PodState:
    metadata = document.get("metadata", {})
    spec = document.get("spec", {})
    status = document.get("status", {})
    containers = status.get("containerStatuses", []) or []
    waiting = tuple(
        c["state"]["waiting"].get("reason", "")
        for c in containers
        if (c.get("state") or {}).get("waiting")
    )
    terminations = tuple(
        ContainerTermination(
            reason=c["lastState"]["terminated"].get("reason", ""),
            exit_code=int(c["lastState"]["terminated"].get("exitCode", 0)),
        )
        for c in containers
        if (c.get("lastState") or {}).get("terminated")
    )
    ready = any(
        cond.get("type") == "Ready" and cond.get("status") == "True"
        for cond in status.get("conditions", []) or []
    )
    return PodState(
        name=metadata["name"],
        phase=status.get("phase", "Unknown"),
        ready=ready,
        restart_count=sum(int(c.get("restartCount", 0)) for c in containers),
        waiting_reasons=waiting,
        last_terminations=terminations,
        started_at=_ts(status.get("startTime")),
        node=spec.get("nodeName"),
    )


def node_state(document: dict[str, Any]) -> NodeState:
    metadata = document.get("metadata", {})
    labels = metadata.get("labels", {}) or {}
    conditions = (document.get("status") or {}).get("conditions", []) or []
    ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)
    pressure = tuple(
        sorted(
            c["type"]
            for c in conditions
            if str(c.get("type", "")).endswith("Pressure") and c.get("status") == "True"
        )
    )
    return NodeState(
        name=metadata["name"],
        resource_version=metadata.get("resourceVersion", ""),
        ready=ready,
        unschedulable=bool((document.get("spec") or {}).get("unschedulable", False)),
        pressure=pressure,
        control_plane="node-role.kubernetes.io/control-plane" in labels,
    )


def parsed[T](convert: Callable[[dict[str, Any]], T], document: Any) -> T:
    """Convert an API object, turning malformed documents into an integration error."""
    try:
        return convert(document)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise IntegrationError(f"unexpected Kubernetes API object: {exc!r}") from exc


class KubernetesApiClient:
    def __init__(self, http: httpx.AsyncClient, *, token: TokenProvider) -> None:
        self._http = http
        self._token = token

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json_body: Any = None,
        content_type: str | None = None,
    ) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self._token()}", "Accept": "application/json"}
        if content_type:
            headers["Content-Type"] = content_type
        try:
            response = await self._http.request(
                method, path, params=params, json=json_body, headers=headers
            )
        except httpx.TimeoutException as exc:
            raise IntegrationUnavailableError(f"Kubernetes API timeout on {path}") from exc
        except httpx.TransportError as exc:
            raise IntegrationUnavailableError(f"Kubernetes API unreachable: {exc}") from exc
        if response.status_code == 404:
            raise TargetNotFoundError(f"{path} not found")
        if response.status_code in (401, 403):
            raise ForbiddenError(f"Kubernetes API refused {method} {path}")
        if response.status_code in (409, 422) and method == "PATCH":
            raise ConflictError(f"Kubernetes API rejected the patch: {self._message(response)}")
        if response.status_code >= 500 or response.status_code == 429:
            raise IntegrationUnavailableError(f"Kubernetes API returned {response.status_code}")
        if response.status_code >= 400:
            raise IntegrationError(
                f"Kubernetes API returned {response.status_code}: {self._message(response)}"
            )
        body: dict[str, Any] = response.json()
        return body

    @staticmethod
    def _message(response: httpx.Response) -> str:
        try:
            return str(response.json().get("message", ""))[:500]
        except ValueError:
            return response.text[:500]

    @staticmethod
    def _mutation_params(dry_run: bool) -> dict[str, str]:
        params = {"fieldManager": FIELD_MANAGER}
        if dry_run:
            params["dryRun"] = "All"
        return params

    @staticmethod
    def _deployment_path(namespace: str, name: str) -> str:
        return f"/apis/apps/v1/namespaces/{quote(namespace)}/deployments/{quote(name)}"

    async def get_deployment(self, namespace: str, name: str) -> DeploymentState:
        return parsed(
            deployment_state, await self._request("GET", self._deployment_path(namespace, name))
        )

    async def list_replicasets(
        self, namespace: str, selector: dict[str, str]
    ) -> Sequence[ReplicaSetState]:
        body = await self._request(
            "GET",
            f"/apis/apps/v1/namespaces/{quote(namespace)}/replicasets",
            params={"labelSelector": _selector(selector)},
        )
        return [parsed(replicaset_state, item) for item in body.get("items", [])]

    async def list_pods(self, namespace: str, selector: dict[str, str]) -> Sequence[PodState]:
        body = await self._request(
            "GET",
            f"/api/v1/namespaces/{quote(namespace)}/pods",
            params={"labelSelector": _selector(selector)},
        )
        return [parsed(pod_state, item) for item in body.get("items", [])]

    async def get_node(self, name: str) -> NodeState:
        return parsed(node_state, await self._request("GET", f"/api/v1/nodes/{quote(name)}"))

    async def list_nodes(self) -> Sequence[NodeState]:
        body = await self._request("GET", "/api/v1/nodes")
        return [parsed(node_state, item) for item in body.get("items", [])]

    async def restart_deployment(
        self, namespace: str, name: str, *, at: datetime, dry_run: bool
    ) -> DeploymentState:
        patch = {
            "spec": {"template": {"metadata": {"annotations": {RESTARTED_AT: at.isoformat()}}}}
        }
        body = await self._request(
            "PATCH",
            self._deployment_path(namespace, name),
            params=self._mutation_params(dry_run),
            json_body=patch,
            content_type=STRATEGIC,
        )
        return parsed(deployment_state, body)

    async def scale_deployment(
        self, namespace: str, name: str, replicas: int, *, dry_run: bool
    ) -> DeploymentState:
        await self._request(
            "PATCH",
            self._deployment_path(namespace, name) + "/scale",
            params=self._mutation_params(dry_run),
            json_body={"spec": {"replicas": replicas}},
            content_type=MERGE,
        )
        current = await self.get_deployment(namespace, name)
        if dry_run:
            # The scale subresource answers with a Scale object; report the would-be spec.
            return current.model_copy(update={"replicas": replicas})
        return current

    async def replace_pod_template(
        self,
        namespace: str,
        name: str,
        template: dict[str, Any],
        *,
        resource_version: str,
        dry_run: bool,
    ) -> DeploymentState:
        patch = [
            {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
            {"op": "replace", "path": "/spec/template", "value": template},
        ]
        body = await self._request(
            "PATCH",
            self._deployment_path(namespace, name),
            params=self._mutation_params(dry_run),
            json_body=patch,
            content_type=JSON_PATCH,
        )
        return parsed(deployment_state, body)

    async def set_unschedulable(
        self, name: str, unschedulable: bool, *, dry_run: bool
    ) -> NodeState:
        body = await self._request(
            "PATCH",
            f"/api/v1/nodes/{quote(name)}",
            params=self._mutation_params(dry_run),
            json_body={"spec": {"unschedulable": unschedulable}},
            content_type=STRATEGIC,
        )
        return parsed(node_state, body)
