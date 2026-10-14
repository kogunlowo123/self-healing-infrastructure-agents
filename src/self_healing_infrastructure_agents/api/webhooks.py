"""Alert ingestion endpoints.

* ``POST /v1/alerts/alertmanager``: Alertmanager ``webhook_configs`` receiver,
  authenticated with the bearer token configured in Alertmanager's
  ``http_config.authorization`` (compared in constant time).
* ``POST /v1/alerts/cloudwatch``: Amazon SNS HTTPS subscription carrying
  CloudWatch alarm state changes; every message is signature-verified.
"""

from __future__ import annotations

import hmac
import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, Request
from pydantic import ValidationError

from self_healing_infrastructure_agents.api.deps import container
from self_healing_infrastructure_agents.api.schemas import SnsAck
from self_healing_infrastructure_agents.application.incidents import IngestResult
from self_healing_infrastructure_agents.domain.errors import (
    HealingError,
    NotFoundError,
    UnauthorizedError,
)
from self_healing_infrastructure_agents.ingestion.alertmanager import (
    AlertmanagerWebhook,
    parse_alertmanager,
)
from self_healing_infrastructure_agents.ingestion.cloudwatch import (
    alert_from_alarm,
    parse_alarm_message,
)
from self_healing_infrastructure_agents.runtime.container import Container
from self_healing_infrastructure_agents.security.jwks import bearer_token
from self_healing_infrastructure_agents.security.sns import SnsEnvelope

MAX_NOTIFICATION_BYTES = 1024 * 1024

router = APIRouter(prefix="/v1/alerts", tags=["ingestion"])
Deps = Annotated[Container, Depends(container)]


async def _body(request: Request) -> tuple[bytes, Any]:
    raw = await request.body()
    if len(raw) > MAX_NOTIFICATION_BYTES:
        raise HealingError("notification exceeds 1 MiB")
    try:
        return raw, json.loads(raw)
    except ValueError as exc:
        raise HealingError("notification body is not JSON") from exc


@router.post("/alertmanager", status_code=202)
async def alertmanager(
    request: Request, c: Deps, authorization: Annotated[str | None, Header()] = None
) -> IngestResult:
    expected = c.settings.alertmanager_token
    if expected is None:
        raise NotFoundError("Alertmanager ingestion is not configured")
    try:
        presented = bearer_token(authorization)
    except UnauthorizedError:
        c.metrics.webhook_rejections.labels("alertmanager", "missing_token").inc()
        raise
    if not hmac.compare_digest(presented.encode(), expected.get_secret_value().encode()):
        c.metrics.webhook_rejections.labels("alertmanager", "bad_token").inc()
        raise UnauthorizedError("invalid webhook credential")
    raw, document = await _body(request)
    try:
        webhook = AlertmanagerWebhook.model_validate(document)
    except ValidationError as exc:
        c.metrics.webhook_rejections.labels("alertmanager", "invalid_payload").inc()
        raise HealingError(f"not an Alertmanager v4 webhook: {exc.error_count()} errors") from exc
    alerts = parse_alertmanager(
        webhook,
        raw,
        received_at=c.clock.now(),
        default_environment=c.settings.default_alert_environment,
    )
    return await c.incidents.ingest(alerts, received_by=f"alertmanager:{webhook.receiver}")


@router.post("/cloudwatch")
async def cloudwatch(request: Request, c: Deps) -> SnsAck:
    raw, document = await _body(request)
    if not isinstance(document, dict):
        raise HealingError("SNS envelope must be a JSON object")
    try:
        envelope = SnsEnvelope.parse(document)
    except ValidationError as exc:
        c.metrics.webhook_rejections.labels("cloudwatch", "invalid_envelope").inc()
        raise HealingError("not an Amazon SNS message") from exc
    try:
        await c.sns.verify(envelope)
    except UnauthorizedError:
        c.metrics.webhook_rejections.labels("cloudwatch", "bad_signature").inc()
        raise
    if envelope.type == "SubscriptionConfirmation":
        await c.sns.confirm_subscription(envelope)
        return SnsAck(status="subscribed")
    if envelope.type == "UnsubscribeConfirmation":
        return SnsAck(status="unsubscribed")
    alarm = parse_alarm_message(envelope.message)
    alert = alert_from_alarm(
        alarm,
        raw,
        received_at=c.clock.now(),
        default_environment=c.settings.default_alert_environment,
    )
    if alert is None:
        return SnsAck(status="ignored")
    result = await c.incidents.ingest([alert], received_by=f"sns:{envelope.topic_arn}")
    return SnsAck(
        status="accepted",
        accepted=result.accepted,
        opened=list(result.opened),
        resolved=list(result.resolved),
    )
