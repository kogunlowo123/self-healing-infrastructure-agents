"""Shared FastAPI dependencies."""

from __future__ import annotations

from fastapi import Request

from self_healing_infrastructure_agents.runtime.container import Container


def container(request: Request) -> Container:
    value: Container = request.app.state.container
    return value
