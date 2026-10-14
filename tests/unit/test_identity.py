"""Identity fabric client, own credential, and caller authorization (fabric and local)."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from agentic_core.domain.classification import Decision
from agentic_core.policy import PolicyEngine, PolicySet

from self_healing_infrastructure_agents.domain.errors import (
    ForbiddenError,
    IntegrationError,
    IntegrationUnavailableError,
    UnauthorizedError,
)
from self_healing_infrastructure_agents.domain.models import (
    PrincipalKind,
    expand_scopes,
    scope_matches,
)
from self_healing_infrastructure_agents.integrations.identity_fabric import (
    JWT_BEARER,
    FabricCredential,
    IdentityFabricClient,
)
from self_healing_infrastructure_agents.security.callers import (
    CallerResolver,
    FabricAgentAuthorizer,
    LocalAgentAuthorizer,
    delegation_depth,
)
from self_healing_infrastructure_agents.security.jwks import RemoteJwks, StaticJwks, verify_jwt
from self_healing_infrastructure_agents.security.operators import OperatorAuthenticator
from tests.conftest import (
    AGENT_AUDIENCE,
    AGENT_ISSUER,
    OPERATOR_AUDIENCE,
    OPERATOR_ISSUER,
    ROOT,
    FakeClock,
    FakeIdp,
    agent_headers,
    operator_headers,
)

FABRIC = "https://identity.corp.test"
AGENT = "spiffe://agents.corp.test/agent/sre/triage"


class FakeFabric:
    """Speaks the identity fabric's wire formats."""

    def __init__(self, decision: str = "allow", active: bool = True) -> None:
        self.decision = decision
        self.active = active
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/oauth2/token":
            form = parse_qs(request.content.decode())
            if form["grant_type"] != [JWT_BEARER]:
                return httpx.Response(
                    400, json={"error": "unsupported_grant_type", "error_description": "x"}
                )
            return httpx.Response(
                200,
                json={
                    "access_token": f"cred-{len(self.requests)}",
                    "token_type": "Bearer",
                    "expires_in": 600,
                    "scope": form.get("scope", [""])[0],
                    "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
                },
            )
        if path == "/oauth2/introspect":
            if not self.active:
                return httpx.Response(200, json={"active": False})
            return httpx.Response(
                200,
                json={
                    "active": True,
                    "sub": AGENT,
                    "scope": "remediation:* incidents:read",
                    "exp": 2_000_000_000,
                    "agent_status": "active",
                },
            )
        if path == "/v1/authorize":
            body = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "decision": self.decision,
                    "agent": AGENT,
                    "action": body["action"],
                    "resource": f"{body['resource_type']}:{body['resource_id']}",
                    "matched_rules": ["allow-scoped-actions"],
                    "policy_version": "2026.10.0",
                    "policy_digest": "sha256:abc",
                    "reason": "explicit allow",
                    "delegation_chain": [AGENT],
                },
            )
        return httpx.Response(404, json={"error": "not_found", "error_description": path})


def fabric_client(handler: Any) -> IdentityFabricClient:
    return IdentityFabricClient(FABRIC, httpx.AsyncClient(transport=httpx.MockTransport(handler)))


class TestFabricClient:
    async def test_wire_formats(self) -> None:
        fake = FakeFabric()
        client = fabric_client(fake)
        issued = await client.issue_token(
            client_id=AGENT, assertion="workload-jwt", scopes=frozenset({"b", "a"})
        )
        assert issued.access_token == "cred-1"
        assert issued.expires_in == 600
        form = parse_qs(fake.requests[0].content.decode())
        assert form["scope"] == ["a b"]
        assert form["client_id"] == [AGENT]
        introspection = await client.introspect("tok")
        assert introspection.scopes == {"remediation:*", "incidents:read"}
        decision = await client.authorize("tok", action="k8s:scale", resource_type="k8s:deployment")
        assert decision.decision is Decision.ALLOW
        authorize = fake.requests[-1]
        assert authorize.headers["authorization"] == "Bearer tok"
        assert json.loads(authorize.content)["resource_classification"] == 1

    @pytest.mark.parametrize(
        ("response", "error"),
        [
            (
                httpx.Response(401, json={"error": "unauthorized", "error_description": "bad"}),
                UnauthorizedError,
            ),
            (
                httpx.Response(403, json={"error": "forbidden", "error_description": "no"}),
                ForbiddenError,
            ),
            (
                httpx.Response(400, json={"error": "invalid_grant", "error_description": "x"}),
                UnauthorizedError,
            ),
            (httpx.Response(502, text="bad gateway"), IntegrationUnavailableError),
            (httpx.Response(200, text="<html>"), IntegrationError),
            (httpx.Response(200, json={"unexpected": True}), IntegrationError),
        ],
    )
    async def test_errors(self, response: httpx.Response, error: type[Exception]) -> None:
        with pytest.raises(error):
            await fabric_client(lambda _: response).introspect("t")

    async def test_unreachable(self) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        with pytest.raises(IntegrationUnavailableError):
            await fabric_client(down).introspect("t")


class TestFabricCredential:
    async def test_cached_until_refresh_margin(self) -> None:
        fake = FakeFabric()
        clock = FakeClock()
        credential = FabricCredential(
            fabric_client(fake),
            agent_id=AGENT,
            workload_token=lambda: "sa-token",
            scopes=frozenset({"k8s:scale"}),
            clock=clock,
        )
        first = await credential.token()
        assert await credential.token() == first
        clock.advance(541)  # 600 s lifetime minus the 60 s margin
        assert await credential.token() != first
        assert credential.agent_id == AGENT
        assert sum(r.url.path == "/oauth2/token" for r in fake.requests) == 2


class TestAuthorizers:
    async def test_fabric_authorizer_caches_introspection(self) -> None:
        fake = FakeFabric()
        authorizer = FabricAgentAuthorizer(fabric_client(fake), clock=FakeClock(), cache_size=1)
        for _ in range(3):
            decision = await authorizer.authorize(
                "tok", action="remediation:propose", resource_type="remediation", resource_id="*"
            )
        assert decision.principal.subject == AGENT
        assert decision.principal.kind is PrincipalKind.AGENT
        assert sum(r.url.path == "/oauth2/introspect" for r in fake.requests) == 1
        await authorizer.authorize("tok-2", action="a", resource_type="r", resource_id="*")
        assert len(authorizer._cache) == 1  # bounded

    async def test_fabric_inactive_token(self) -> None:
        authorizer = FabricAgentAuthorizer(
            fabric_client(FakeFabric(active=False)), clock=FakeClock()
        )
        with pytest.raises(UnauthorizedError, match="not active"):
            await authorizer.authorize("t", action="a", resource_type="r", resource_id="*")

    async def test_fabric_require_approval_marks_principal(self) -> None:
        authorizer = FabricAgentAuthorizer(
            fabric_client(FakeFabric(decision="require_approval")), clock=FakeClock()
        )
        decision = await authorizer.authorize(
            "t", action="remediation:propose", resource_type="r", resource_id="*"
        )
        assert decision.principal.requires_approval

    def local(self, idp: FakeIdp, clock: FakeClock) -> LocalAgentAuthorizer:
        return LocalAgentAuthorizer(
            StaticJwks(idp.jwks()),
            PolicyEngine(PolicySet.from_file(ROOT / "policies" / "agent-access.yaml")),
            issuer=AGENT_ISSUER,
            audience=AGENT_AUDIENCE,
            clock=clock,
        )

    async def test_local_scope_and_delegation(self, agent_idp: FakeIdp, clock: FakeClock) -> None:
        authorizer = self.local(agent_idp, clock)
        token = agent_idp.mint(sub=AGENT, aud=AGENT_AUDIENCE, scope="remediation:*")
        allowed = await authorizer.authorize(
            token, action="remediation:propose", resource_type="remediation", resource_id="*"
        )
        assert allowed.decision is Decision.ALLOW
        denied = await authorizer.authorize(
            token, action="incidents:read", resource_type="incident", resource_id="*"
        )
        assert denied.decision is Decision.DENY
        delegated = agent_idp.mint(
            sub=AGENT, aud=AGENT_AUDIENCE, scope="remediation:propose", act={"sub": "spiffe://x"}
        )
        held = await authorizer.authorize(
            delegated, action="remediation:propose", resource_type="remediation", resource_id="*"
        )
        assert held.decision is Decision.REQUIRE_APPROVAL
        deep = agent_idp.mint(
            sub=AGENT,
            aud=AGENT_AUDIENCE,
            scope="remediation:propose",
            act={"sub": "a", "act": {"sub": "b"}},
        )
        too_deep = await authorizer.authorize(
            deep, action="remediation:propose", resource_type="remediation", resource_id="*"
        )
        assert too_deep.decision is Decision.DENY

    def test_scope_matching(self) -> None:
        assert scope_matches("remediation:*", "remediation:execute")
        assert scope_matches("incidents:read", "incidents:read")
        assert not scope_matches("remediation:*", "incidents:read")
        assert not scope_matches("remediation", "remediation:execute")
        assert "remediation:execute" in expand_scopes(frozenset({"remediation:*"}))
        assert expand_scopes(frozenset({"incidents:read"})) == {"incidents:read"}
        assert delegation_depth(None) == 0
        assert delegation_depth({"sub": "a", "act": {"sub": "b"}}) == 2


class TestCallerResolver:
    def resolver(
        self, operator_idp: FakeIdp, agent_idp: FakeIdp, clock: FakeClock
    ) -> CallerResolver:
        return CallerResolver(
            operators=OperatorAuthenticator(
                StaticJwks(operator_idp.jwks()),
                issuer=OPERATOR_ISSUER,
                audience=OPERATOR_AUDIENCE,
                clock=clock,
            ),
            operator_issuer=OPERATOR_ISSUER,
            agents=TestAuthorizers().local(agent_idp, clock),
        )

    async def test_routes_by_issuer(
        self, operator_idp: FakeIdp, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        resolver = self.resolver(operator_idp, agent_idp, clock)
        operator = await resolver.resolve(
            operator_headers(operator_idp, "remediation-operator")["Authorization"],
            action="remediation:execute",
            resource_type="remediation",
        )
        assert operator.kind is PrincipalKind.USER
        assert operator.subject == "user:alice@corp.test"
        agent = await resolver.resolve(
            agent_headers(agent_idp, "incidents:read")["Authorization"],
            action="incidents:read",
            resource_type="incident",
        )
        assert agent.kind is PrincipalKind.AGENT

    async def test_denials(
        self, operator_idp: FakeIdp, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        resolver = self.resolver(operator_idp, agent_idp, clock)
        with pytest.raises(ForbiddenError):
            await resolver.resolve(
                operator_headers(operator_idp, "remediation-viewer")["Authorization"],
                action="remediation:execute",
                resource_type="remediation",
            )
        with pytest.raises(ForbiddenError, match="denied"):
            await resolver.resolve(
                agent_headers(agent_idp, "incidents:read")["Authorization"],
                action="remediation:execute",
                resource_type="remediation",
            )
        held = agent_headers(agent_idp, "incidents:read", act={"sub": "spiffe://x"})
        assert (
            await resolver.resolve(
                held["Authorization"], action="incidents:read", resource_type="incident"
            )
        ).requires_approval is False
        with pytest.raises(UnauthorizedError):
            await resolver.resolve("Bearer not-a-jwt", action="incidents:read", resource_type="i")
        with pytest.raises(UnauthorizedError):
            await resolver.resolve(None, action="incidents:read", resource_type="i")

    async def test_require_approval_only_for_approvable_actions(
        self, operator_idp: FakeIdp, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        policy = PolicySet.model_validate(
            {
                "name": "p",
                "version": "1",
                "rules": [{"id": "hold", "effect": "require_approval", "actions": ["*"]}],
            }
        )
        resolver = CallerResolver(
            operators=OperatorAuthenticator(
                StaticJwks(operator_idp.jwks()),
                issuer=OPERATOR_ISSUER,
                audience=OPERATOR_AUDIENCE,
                clock=clock,
            ),
            operator_issuer=OPERATOR_ISSUER,
            agents=LocalAgentAuthorizer(
                StaticJwks(agent_idp.jwks()),
                PolicyEngine(policy),
                issuer=AGENT_ISSUER,
                audience=AGENT_AUDIENCE,
                clock=clock,
            ),
        )
        token = agent_headers(agent_idp, "x")["Authorization"]
        principal = await resolver.resolve(token, action="remediation:propose", resource_type="r")
        assert principal.requires_approval
        with pytest.raises(ForbiddenError, match="cannot be held"):
            await resolver.resolve(token, action="incidents:read", resource_type="r")


class TestJwt:
    async def test_time_claims_use_injected_clock(
        self, agent_idp: FakeIdp, clock: FakeClock
    ) -> None:
        resolver = StaticJwks(agent_idp.jwks())
        token = agent_idp.mint(sub="s", aud="a", ttl=60)
        now = clock.now().timestamp()
        assert (await verify_jwt(token, resolver, issuer=AGENT_ISSUER, audience="a", now=now))[
            "sub"
        ] == "s"
        with pytest.raises(UnauthorizedError, match="expired"):
            await verify_jwt(token, resolver, issuer=AGENT_ISSUER, audience="a", now=now + 120)
        with pytest.raises(UnauthorizedError, match="not yet valid"):
            await verify_jwt(token, resolver, issuer=AGENT_ISSUER, audience="a", now=now - 120)
        future = agent_idp.mint(sub="s", aud="a", nbf=int(now) + 300)
        with pytest.raises(UnauthorizedError, match="not yet valid"):
            await verify_jwt(future, resolver, issuer=AGENT_ISSUER, audience="a", now=now)

    async def test_rejections(self, agent_idp: FakeIdp, clock: FakeClock) -> None:
        resolver = StaticJwks(agent_idp.jwks())
        now = clock.now().timestamp()
        for token, match in (
            ("garbage", "malformed"),
            (agent_idp.mint(sub="s", aud="other"), "rejected"),
            (agent_idp.mint(sub="s", aud="a", exp="soon"), "malformed"),
        ):
            with pytest.raises(UnauthorizedError, match=match):
                await verify_jwt(token, resolver, issuer=AGENT_ISSUER, audience="a", now=now)
        with pytest.raises(UnauthorizedError, match="unknown signing key"):
            await resolver.key_for("nope")

    async def test_remote_jwks_refresh_and_outage(self, agent_idp: FakeIdp) -> None:
        calls = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] > 1:
                return httpx.Response(503)
            return httpx.Response(200, json=agent_idp.jwks())

        ticks = iter([0.0, 0.0, 400.0, 400.0])
        remote = RemoteJwks(
            "https://identity.corp.test/jwks",
            client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            clock=lambda: next(ticks),
        )
        assert await remote.key_for(agent_idp.kid) is not None
        # Stale cache and failed refresh: known keys keep working, unknown ones fail closed.
        assert await remote.key_for(agent_idp.kid) is not None
        with pytest.raises(UnauthorizedError, match="cannot fetch"):
            await remote.key_for("rotated-away")
