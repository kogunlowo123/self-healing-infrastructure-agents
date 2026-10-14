"""Human operator authentication via the enterprise OIDC provider.

Roles come from the IdP and map to the scopes the remediation policy checks:

* ``remediation-viewer``    read incidents and plans
* ``remediation-operator``  propose remediations, run dry runs and live executions
* ``remediation-approver``  approve or reject plans (never their own)
"""

from __future__ import annotations

from self_healing_infrastructure_agents.domain.errors import ForbiddenError
from self_healing_infrastructure_agents.domain.models import Principal, PrincipalKind
from self_healing_infrastructure_agents.domain.ports import Clock
from self_healing_infrastructure_agents.security.jwks import KeyResolver, bearer_token, verify_jwt


class OperatorRole:
    VIEWER = "remediation-viewer"
    OPERATOR = "remediation-operator"
    APPROVER = "remediation-approver"


ROLE_SCOPES: dict[str, frozenset[str]] = {
    OperatorRole.VIEWER: frozenset({"incidents:read", "remediation:read"}),
    OperatorRole.OPERATOR: frozenset(
        {
            "incidents:read",
            "remediation:read",
            "alerts:diagnose",
            "terraform:analyze",
            "remediation:propose",
            "remediation:dry-run",
            "remediation:execute",
        }
    ),
    OperatorRole.APPROVER: frozenset({"incidents:read", "remediation:read", "remediation:approve"}),
}


class OperatorAuthenticator:
    def __init__(
        self,
        resolver: KeyResolver,
        *,
        issuer: str,
        audience: str,
        clock: Clock,
        roles_claim: str = "roles",
    ) -> None:
        self._resolver = resolver
        self._issuer = issuer
        self._audience = audience
        self._clock = clock
        self._roles_claim = roles_claim

    async def authenticate(self, authorization: str | None) -> Principal:
        claims = await verify_jwt(
            bearer_token(authorization),
            self._resolver,
            issuer=self._issuer,
            audience=self._audience,
            now=self._clock.now().timestamp(),
        )
        raw = claims.get(self._roles_claim, [])
        roles = (
            frozenset(r for r in raw if isinstance(r, str) and r in ROLE_SCOPES)
            if isinstance(raw, list)
            else frozenset()
        )
        scopes: frozenset[str] = frozenset().union(*(ROLE_SCOPES[r] for r in roles))
        return Principal(
            subject=f"user:{claims['sub']}",
            kind=PrincipalKind.USER,
            roles=roles,
            scopes=scopes,
        )


def require_scope(principal: Principal, scope: str) -> None:
    if scope not in principal.scopes:
        raise ForbiddenError(f"{principal.subject} lacks {scope}")
