"""Inbound caller authorization for HTTP, MCP and A2A requests.

Two kinds of caller present bearer tokens:

* human operators, with an enterprise OIDC token (roles -> scopes);
* agents, with an agent credential issued by the identity fabric.

Agent requests are authorized by the fabric's ``/v1/authorize`` decision
point when ``HEAL_FABRIC_URL`` is configured. Otherwise the agent credential
is verified locally against the fabric's JWKS and evaluated by a local
PolicyEngine with the same semantics. There is no configuration in which
an unauthenticated or unscoped caller is allowed.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections import OrderedDict
from typing import Any, Protocol

from agentic_core.domain.classification import Decision
from agentic_core.policy import PolicyEngine, PolicyRequest, Resource, Subject
from pydantic import BaseModel, ConfigDict

from self_healing_infrastructure_agents.domain.errors import ForbiddenError, UnauthorizedError
from self_healing_infrastructure_agents.domain.models import (
    Principal,
    PrincipalKind,
    scope_matches,
)
from self_healing_infrastructure_agents.domain.ports import Clock
from self_healing_infrastructure_agents.integrations.identity_fabric import (
    IdentityFabricClient,
    Introspection,
)
from self_healing_infrastructure_agents.security.jwks import KeyResolver, bearer_token, verify_jwt
from self_healing_infrastructure_agents.security.operators import (
    OperatorAuthenticator,
    require_scope,
)

# Actions under which a require_approval outcome is meaningful: the request is
# accepted but whatever it creates or runs is held for a human approver.
APPROVABLE_ACTIONS = frozenset({"remediation:propose", "remediation:execute"})


class CallerDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    principal: Principal
    decision: Decision
    matched_rules: tuple[str, ...] = ()
    policy_version: str = ""
    reason: str = ""


class AgentAuthorizer(Protocol):
    async def authorize(
        self, token: str, *, action: str, resource_type: str, resource_id: str
    ) -> CallerDecision: ...


def delegation_depth(act: Any) -> int:
    depth = 0
    while isinstance(act, dict) and depth < 16:
        depth += 1
        act = act.get("act")
    return depth


class LocalAgentAuthorizer:
    """Verifies fabric-issued agent credentials against JWKS; decides with local policy."""

    def __init__(
        self,
        resolver: KeyResolver,
        policy: PolicyEngine,
        *,
        issuer: str,
        audience: str,
        clock: Clock,
    ) -> None:
        self._resolver = resolver
        self._policy = policy
        self._issuer = issuer
        self._audience = audience
        self._clock = clock

    async def authorize(
        self, token: str, *, action: str, resource_type: str, resource_id: str
    ) -> CallerDecision:
        claims = await verify_jwt(
            token,
            self._resolver,
            issuer=self._issuer,
            audience=self._audience,
            now=self._clock.now().timestamp(),
        )
        scopes = frozenset(str(claims.get("scope", "")).split())
        depth = delegation_depth(claims.get("act"))
        decision = self._policy.evaluate(
            PolicyRequest(
                subject=Subject(
                    id=str(claims["sub"]),
                    kind="agent",
                    attributes={
                        "status": "active",
                        "scopes": sorted(scopes),
                        "action_in_scope": any(scope_matches(s, action) for s in scopes),
                        "delegated": depth > 0,
                        "delegation_depth": depth,
                    },
                ),
                action=action,
                resource=Resource(type=resource_type, id=resource_id),
            )
        )
        return CallerDecision(
            principal=Principal(
                subject=str(claims["sub"]),
                kind=PrincipalKind.AGENT,
                scopes=scopes,
                requires_approval=decision.decision is Decision.REQUIRE_APPROVAL,
            ),
            decision=decision.decision,
            matched_rules=decision.matched_rules,
            policy_version=decision.policy_version,
            reason=decision.reason,
        )


class FabricAgentAuthorizer:
    """Delegates the decision to the identity fabric; caches introspection briefly."""

    def __init__(
        self,
        client: IdentityFabricClient,
        *,
        clock: Clock,
        cache_seconds: int = 30,
        cache_size: int = 1024,
    ) -> None:
        self._client = client
        self._clock = clock
        self._ttl = cache_seconds
        self._size = cache_size
        self._cache: OrderedDict[str, tuple[float, Introspection]] = OrderedDict()

    async def _introspect(self, token: str) -> Introspection:
        key = hashlib.sha256(token.encode()).hexdigest()
        now = self._clock.now().timestamp()
        cached = self._cache.get(key)
        if cached is not None and cached[0] > now:
            return cached[1]
        result = await self._client.introspect(token)
        if result.active:
            until = min(now + self._ttl, float(result.exp or now))
            self._cache[key] = (until, result)
            self._cache.move_to_end(key)
            while len(self._cache) > self._size:
                self._cache.popitem(last=False)
        return result

    async def authorize(
        self, token: str, *, action: str, resource_type: str, resource_id: str
    ) -> CallerDecision:
        introspection = await self._introspect(token)
        if not introspection.active or not introspection.sub:
            raise UnauthorizedError("agent credential is not active")
        decision = await self._client.authorize(
            token, action=action, resource_type=resource_type, resource_id=resource_id
        )
        return CallerDecision(
            principal=Principal(
                subject=introspection.sub,
                kind=PrincipalKind.AGENT,
                scopes=introspection.scopes,
                requires_approval=decision.decision is Decision.REQUIRE_APPROVAL,
            ),
            decision=decision.decision,
            matched_rules=decision.matched_rules,
            policy_version=decision.policy_version,
            reason=decision.reason,
        )


def _unverified_issuer(token: str) -> str | None:
    """Routing hint only: which verifier to use. The chosen verifier checks everything."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except ValueError:
        return None
    issuer = claims.get("iss") if isinstance(claims, dict) else None
    return issuer if isinstance(issuer, str) else None


class CallerResolver:
    def __init__(
        self,
        *,
        operators: OperatorAuthenticator,
        operator_issuer: str,
        agents: AgentAuthorizer,
    ) -> None:
        self._operators = operators
        self._operator_issuer = operator_issuer
        self._agents = agents

    async def operator(self, authorization: str | None, *, scope: str) -> Principal:
        principal = await self._operators.authenticate(authorization)
        require_scope(principal, scope)
        return principal

    async def resolve(
        self,
        authorization: str | None,
        *,
        action: str,
        resource_type: str,
        resource_id: str = "*",
    ) -> Principal:
        token = bearer_token(authorization)
        if _unverified_issuer(token) == self._operator_issuer:
            return await self.operator(authorization, scope=action)
        decision = await self._agents.authorize(
            token, action=action, resource_type=resource_type, resource_id=resource_id
        )
        if decision.decision is Decision.DENY:
            raise ForbiddenError(
                f"{action} denied for {decision.principal.subject}: {decision.reason}"
            )
        if decision.decision is Decision.REQUIRE_APPROVAL and action not in APPROVABLE_ACTIONS:
            raise ForbiddenError(f"{action} needs human approval and cannot be held for it")
        return decision.principal
