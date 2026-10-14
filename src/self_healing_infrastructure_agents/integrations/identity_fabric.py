"""Typed client for the agent identity fabric.

Wire formats follow the fabric's published contracts:

* ``POST /oauth2/token``      RFC 7523 jwt-bearer grant (workload token -> agent credential)
* ``POST /v1/authorize``      policy decision for an action on a resource
* ``POST /oauth2/introspect`` RFC 7662 token introspection
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any

import httpx
from agentic_core.domain.classification import DataClassification, Decision
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from self_healing_infrastructure_agents.domain.errors import (
    ForbiddenError,
    IntegrationError,
    IntegrationUnavailableError,
    UnauthorizedError,
)
from self_healing_infrastructure_agents.domain.ports import Clock

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class IssuedToken(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    access_token: str
    token_type: str
    expires_in: int = Field(ge=1)
    scope: str = ""


class Introspection(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    active: bool
    sub: str | None = None
    scope: str | None = None
    exp: int | None = None
    iat: int | None = None
    jti: str | None = None
    iss: str | None = None
    aud: str | None = None
    act: dict[str, Any] | None = None
    agent_status: str | None = None

    @property
    def scopes(self) -> frozenset[str]:
        return frozenset((self.scope or "").split())


class FabricDecision(BaseModel):
    model_config = ConfigDict(frozen=True, extra="ignore")

    decision: Decision
    agent: str
    action: str
    resource: str
    matched_rules: tuple[str, ...]
    policy_version: str
    policy_digest: str
    reason: str
    delegation_chain: tuple[str, ...] = ()


class IdentityFabricClient:
    def __init__(self, base_url: str, http: httpx.AsyncClient) -> None:
        self._base = base_url.rstrip("/")
        self._http = http

    async def _post(
        self,
        path: str,
        *,
        data: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        try:
            response = await self._http.post(
                self._base + path, data=data, json=json_body, headers=headers
            )
        except httpx.HTTPError as exc:
            raise IntegrationUnavailableError(f"identity fabric unreachable: {exc}") from exc
        if response.status_code >= 500:
            raise IntegrationUnavailableError(f"identity fabric returned {response.status_code}")
        try:
            body: dict[str, Any] = response.json()
        except ValueError as exc:
            raise IntegrationError("identity fabric returned a non-JSON body") from exc
        if response.status_code == 401:
            raise UnauthorizedError(str(body.get("error_description", "credential rejected")))
        if response.status_code == 403:
            raise ForbiddenError(str(body.get("error_description", "forbidden")))
        if response.status_code >= 400:
            raise UnauthorizedError(
                f"{body.get('error', 'invalid_request')}: {body.get('error_description', '')}"
            )
        return body

    async def issue_token(
        self, *, client_id: str, assertion: str, scopes: frozenset[str] | None = None
    ) -> IssuedToken:
        data = {"grant_type": JWT_BEARER, "client_id": client_id, "assertion": assertion}
        if scopes:
            data["scope"] = " ".join(sorted(scopes))
        return self._parse(IssuedToken, await self._post("/oauth2/token", data=data))

    async def introspect(self, token: str) -> Introspection:
        return self._parse(
            Introspection, await self._post("/oauth2/introspect", data={"token": token})
        )

    async def authorize(
        self,
        token: str,
        *,
        action: str,
        resource_type: str,
        resource_id: str = "*",
        classification: DataClassification = DataClassification.INTERNAL,
        attributes: dict[str, Any] | None = None,
        environment: dict[str, Any] | None = None,
    ) -> FabricDecision:
        body = {
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "resource_classification": int(classification),
            "resource_attributes": attributes or {},
            "environment": environment or {},
        }
        return self._parse(
            FabricDecision, await self._post("/v1/authorize", json_body=body, token=token)
        )

    @staticmethod
    def _parse[M: BaseModel](model: type[M], body: dict[str, Any]) -> M:
        try:
            return model.model_validate(body)
        except ValidationError as exc:
            raise IntegrationError(f"unexpected identity fabric response: {exc}") from exc


class FabricCredential:
    """This service's own agent credential, obtained with its workload token and cached."""

    def __init__(
        self,
        client: IdentityFabricClient,
        *,
        agent_id: str,
        workload_token: Callable[[], str],
        scopes: frozenset[str],
        clock: Clock,
        refresh_margin: timedelta = timedelta(seconds=60),
    ) -> None:
        self._client = client
        self._agent_id = agent_id
        self._workload_token = workload_token
        self._scopes = scopes
        self._clock = clock
        self._margin = refresh_margin
        self._token: str | None = None
        self._expires_at = clock.now()

    @property
    def agent_id(self) -> str:
        return self._agent_id

    async def token(self) -> str:
        now = self._clock.now()
        if self._token is None or now >= self._expires_at - self._margin:
            issued = await self._client.issue_token(
                client_id=self._agent_id, assertion=self._workload_token(), scopes=self._scopes
            )
            self._token = issued.access_token
            self._expires_at = now + timedelta(seconds=issued.expires_in)
        return self._token
