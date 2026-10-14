"""Process entry point: ``python -m self_healing_infrastructure_agents``."""

from __future__ import annotations

import os

import uvicorn
from agentic_core.observability import configure_logging, configure_telemetry
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

from self_healing_infrastructure_agents import __version__
from self_healing_infrastructure_agents.api.app import create_app
from self_healing_infrastructure_agents.config import Settings
from self_healing_infrastructure_agents.runtime.container import build_container

SERVICE = "self-healing-infrastructure-agents"


def main() -> None:
    settings = Settings()  # populated from HEAL_* environment variables
    configure_logging(service=SERVICE, environment=settings.environment, level=settings.log_level)
    exporter = None
    if settings.otlp_endpoint:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # noqa: PLC0415
            OTLPSpanExporter,
        )

        exporter = OTLPSpanExporter(endpoint=settings.otlp_endpoint)
    configure_telemetry(
        service_name=SERVICE,
        service_version=__version__,
        environment=settings.environment,
        span_exporter=exporter,
    )
    app = create_app(lambda: build_container(settings))
    FastAPIInstrumentor.instrument_app(app, excluded_urls="healthz,readyz,metrics")
    uvicorn.run(
        app,
        host=os.environ.get("HEAL_HOST", "127.0.0.1"),
        port=int(os.environ.get("HEAL_PORT", "8080")),
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("HEAL_FORWARDED_ALLOW_IPS", "127.0.0.1"),
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":
    main()
