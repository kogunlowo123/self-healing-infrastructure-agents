"""FastAPI application factory: HTTP API, A2A, MCP, middleware and background sweeps."""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

from agentic_core.observability import bind_correlation_id, get_logger
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from mcp.server.transport_security import TransportSecuritySettings
from starlette.types import ASGIApp, Receive, Scope, Send

from self_healing_infrastructure_agents import __version__
from self_healing_infrastructure_agents.api import a2a, routes, webhooks
from self_healing_infrastructure_agents.api.mcp_tools import build_mcp
from self_healing_infrastructure_agents.domain.errors import HealingError, PolicyViolationError
from self_healing_infrastructure_agents.runtime.container import Container

ContainerFactory = Callable[[], Awaitable[Container]]
MAX_BODY_BYTES = 16 * 1024 * 1024

log = get_logger("self_healing_infrastructure_agents.api")


async def expire_plans_forever(
    container: Container,
    interval_s: float,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> None:
    """Move plans past their approval window to ``expired`` so stale approvals cannot run."""
    while True:
        try:
            await container.remediation.expire_stale()
        except Exception:
            log.exception("plan_expiry_failed")
        await sleep(interval_s)


class McpHostGuard:
    """DNS-rebinding and origin protection in front of the mounted MCP endpoint.

    Allowed hosts come from the running container's settings (public URL by
    default), so the check uses deployment configuration rather than values
    fixed at import time.
    """

    def __init__(self, app: ASGIApp, get_container: Callable[[], Container]) -> None:
        self._app = app
        self._get_container = get_container

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            settings = self._get_container().settings
            headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope["headers"]}
            host = headers.get("host", "")
            origin = headers.get("origin")
            if host not in settings.allowed_hosts or (
                origin is not None and origin.rstrip("/") != settings.public_url_str
            ):
                response = JSONResponse(
                    {"error": "forbidden", "error_description": "host or origin not allowed"},
                    status_code=403,
                )
                await response(scope, receive, send)
                return
        await self._app(scope, receive, send)


def create_app(factory: ContainerFactory, *, sweep_interval_s: float | None = None) -> FastAPI:
    state: dict[str, Any] = {}

    def current() -> Container:
        value: Container = state["container"]
        return value

    mcp = build_mcp(current)
    mcp_app = mcp.streamable_http_app(
        streamable_http_path="/",
        stateless_http=True,
        json_response=True,
        # Host and Origin are enforced by McpHostGuard using deployment settings.
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        container = await factory()
        state["container"] = container
        app.state.container = container
        interval = sweep_interval_s or container.settings.plan_sweep_interval_seconds
        sweeper = asyncio.create_task(expire_plans_forever(container, interval))
        log.info(
            "startup",
            version=__version__,
            execution_mode=container.settings.execution_mode.value,
        )
        try:
            async with mcp.session_manager.run():
                yield
        finally:
            sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sweeper
            await container.aclose()

    app = FastAPI(
        title="Self-Healing Infrastructure Agents",
        version=__version__,
        description=(
            "Alert ingestion, playbook diagnosis, Terraform plan analysis, policy validation, "
            "approval-gated remediation with automatic rollback. Dry run by default."
        ),
        lifespan=lifespan,
    )
    app.include_router(webhooks.router)
    app.include_router(routes.router)
    app.include_router(a2a.router)
    app.mount("/mcp", McpHostGuard(mcp_app, current))

    @app.middleware("http")
    async def correlation_and_metrics(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        length = request.headers.get("content-length")
        if length is not None and (not length.isdigit() or int(length) > MAX_BODY_BYTES):
            return JSONResponse(
                {"error": "invalid_request", "error_description": "request body too large"},
                status_code=413,
            )
        incoming = request.headers.get("x-correlation-id")
        cid = incoming if incoming and len(incoming) <= 64 and incoming.isprintable() else None
        started = time.perf_counter()
        with bind_correlation_id(cid) as bound:
            response = await call_next(request)
        response.headers["X-Correlation-ID"] = bound
        response.headers["X-Content-Type-Options"] = "nosniff"
        route = request.scope.get("route")
        path = getattr(
            route, "path", "/mcp" if request.url.path.startswith("/mcp") else "unmatched"
        )
        container: Container | None = getattr(request.app.state, "container", None)
        if container is not None:
            container.metrics.requests.labels(
                request.method, path, str(response.status_code)
            ).observe(time.perf_counter() - started)
        return response

    @app.exception_handler(HealingError)
    async def healing_error(_: Request, exc: HealingError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None
        content: dict[str, Any] = {"error": exc.code, "error_description": exc.message}
        if isinstance(exc, PolicyViolationError) and exc.rule_ids:
            content["rule_ids"] = list(exc.rule_ids)
        return JSONResponse(status_code=exc.status, content=content, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "invalid_request",
                "error_description": "request failed validation",
                "details": [
                    {"loc": [str(p) for p in e.get("loc", ())], "msg": str(e.get("msg", ""))}
                    for e in exc.errors()
                ],
            },
        )

    return app
