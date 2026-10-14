"""Prometheus Alertmanager webhook (payload version 4) parsing."""

from __future__ import annotations

from datetime import UTC, datetime

from agentic_core.domain.provenance import content_digest
from pydantic import BaseModel, ConfigDict, Field

from self_healing_infrastructure_agents.domain.models import (
    Alert,
    AlertSource,
    AlertStatus,
    Severity,
)
from self_healing_infrastructure_agents.ingestion.targets import target_from_labels

# Alertmanager encodes "no end time" as the Go zero time.
_GO_ZERO_YEAR = 1


class AlertmanagerAlert(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    status: AlertStatus
    labels: dict[str, str] = Field(default_factory=dict, max_length=64)
    annotations: dict[str, str] = Field(default_factory=dict, max_length=64)
    starts_at: datetime = Field(alias="startsAt")
    ends_at: datetime | None = Field(default=None, alias="endsAt")
    generator_url: str | None = Field(default=None, alias="generatorURL", max_length=4096)
    fingerprint: str = Field(min_length=1, max_length=200)


class AlertmanagerWebhook(BaseModel):
    """Body Alertmanager POSTs to a ``webhook_configs`` receiver."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    version: str = Field(pattern=r"^4$")
    group_key: str = Field(alias="groupKey", max_length=4096)
    truncated_alerts: int = Field(default=0, alias="truncatedAlerts", ge=0)
    status: AlertStatus
    receiver: str = Field(max_length=500)
    group_labels: dict[str, str] = Field(default_factory=dict, alias="groupLabels")
    common_labels: dict[str, str] = Field(default_factory=dict, alias="commonLabels")
    common_annotations: dict[str, str] = Field(default_factory=dict, alias="commonAnnotations")
    external_url: str | None = Field(default=None, alias="externalURL", max_length=4096)
    alerts: list[AlertmanagerAlert] = Field(min_length=1, max_length=500)


def _severity(labels: dict[str, str]) -> Severity:
    value = labels.get("severity", "").lower()
    if value in {"critical", "page", "error"}:
        return Severity.CRITICAL
    if value in {"info", "none"}:
        return Severity.INFO
    return Severity.WARNING


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def parse_alertmanager(
    webhook: AlertmanagerWebhook, raw: bytes, *, received_at: datetime, default_environment: str
) -> list[Alert]:
    digest = content_digest(raw)
    alerts: list[Alert] = []
    for item in webhook.alerts:
        labels = {**webhook.common_labels, **item.labels}
        annotations = {**webhook.common_annotations, **item.annotations}
        ends_at = item.ends_at
        if ends_at is not None and ends_at.year <= _GO_ZERO_YEAR:
            ends_at = None
        alerts.append(
            Alert(
                source=AlertSource.ALERTMANAGER,
                fingerprint=f"am:{item.fingerprint}",
                name=labels.get("alertname", "unnamed"),
                status=item.status,
                severity=_severity(labels),
                summary=annotations.get("summary", "")[:2000],
                description=annotations.get("description", "")[:8000],
                labels=labels,
                annotations=annotations,
                starts_at=_aware(item.starts_at),
                ends_at=_aware(ends_at) if ends_at else None,
                target=target_from_labels(labels, default_environment=default_environment),
                payload_digest=digest,
                received_at=received_at,
            )
        )
    return alerts
