"""CloudWatch alarm state-change notifications delivered through Amazon SNS.

The SNS ``Message`` field carries the alarm as a JSON string. Targets are
derived from metric dimensions: Container Insights (``ClusterName`` with
``Namespace`` + ``PodName``/``Service``, or ``NodeName``) map to Kubernetes
objects; anything else (``DBInstanceIdentifier``, ``InstanceId``, ...) is a
cloud resource that is remediated through a reviewed Terraform plan.

Severity and environment come from ``key:value`` tokens in the alarm
description (``severity:critical environment:production``) because the
notification does not carry alarm tags.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

from agentic_core.domain.provenance import content_digest
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError

from self_healing_infrastructure_agents.domain.errors import HealingError
from self_healing_infrastructure_agents.domain.models import (
    Alert,
    AlertSource,
    AlertStatus,
    Severity,
    Target,
    TargetKind,
)

_TOKEN = re.compile(r"\b(severity|environment|env):([A-Za-z0-9_-]+)")


class Dimension(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str = Field(max_length=255)
    value: str = Field(max_length=1024)


class AlarmTrigger(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    metric_name: str | None = Field(default=None, alias="MetricName", max_length=255)
    namespace: str | None = Field(default=None, alias="Namespace", max_length=255)
    statistic: str | None = Field(default=None, alias="Statistic", max_length=64)
    dimensions: list[Dimension] = Field(default_factory=list, alias="Dimensions", max_length=30)
    period: int | None = Field(default=None, alias="Period")
    evaluation_periods: int | None = Field(default=None, alias="EvaluationPeriods")
    comparison_operator: str | None = Field(default=None, alias="ComparisonOperator")
    threshold: float | None = Field(default=None, alias="Threshold")


class CloudWatchAlarm(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    alarm_name: str = Field(alias="AlarmName", min_length=1, max_length=255)
    alarm_description: str | None = Field(default=None, alias="AlarmDescription", max_length=1024)
    account_id: str = Field(alias="AWSAccountId", pattern=r"^\d{12}$")
    new_state: str = Field(alias="NewStateValue")
    old_state: str | None = Field(default=None, alias="OldStateValue")
    reason: str = Field(default="", alias="NewStateReason", max_length=4000)
    state_change_time: AwareDatetime = Field(alias="StateChangeTime")
    region: str = Field(alias="Region", max_length=100)
    alarm_arn: str = Field(alias="AlarmArn", max_length=1024)
    trigger: AlarmTrigger = Field(default_factory=AlarmTrigger, alias="Trigger")


def parse_alarm_message(message: str) -> CloudWatchAlarm:
    try:
        return CloudWatchAlarm.model_validate(json.loads(message))
    except (ValueError, ValidationError) as exc:
        raise HealingError("SNS message is not a CloudWatch alarm notification") from exc


def _tokens(description: str | None) -> dict[str, str]:
    found: dict[str, str] = {}
    for key, value in _TOKEN.findall(description or ""):
        found["environment" if key == "env" else key] = value.lower()
    return found


def _target(alarm: CloudWatchAlarm, environment: str) -> Target | None:
    dims = {d.name: d.value for d in alarm.trigger.dimensions}
    cluster = dims.get("ClusterName")
    try:
        if cluster and dims.get("NodeName"):
            return Target(
                kind=TargetKind.NODE,
                name=dims["NodeName"],
                cluster=cluster,
                environment=environment,
            )
        workload = dims.get("PodName") or dims.get("Service")
        if cluster and dims.get("Namespace") and workload:
            return Target(
                kind=TargetKind.DEPLOYMENT,
                name=workload,
                namespace=dims["Namespace"],
                cluster=cluster,
                environment=environment,
            )
    except ValidationError:
        return None
    if dims:
        name, value = sorted(dims.items())[0]
        return Target(
            kind=TargetKind.CLOUD_RESOURCE,
            name=f"{alarm.trigger.namespace or 'aws'}/{name}={value}"[:253],
            cluster=alarm.region,
            environment=environment,
        )
    return None


def alert_from_alarm(
    alarm: CloudWatchAlarm, raw: bytes, *, received_at: datetime, default_environment: str
) -> Alert | None:
    """Translate an alarm state change; INSUFFICIENT_DATA carries no signal and yields None."""
    if alarm.new_state == "ALARM":
        status = AlertStatus.FIRING
    elif alarm.new_state == "OK":
        status = AlertStatus.RESOLVED
    else:
        return None
    tokens = _tokens(alarm.alarm_description)
    environment = tokens.get("environment", default_environment)
    severity = {
        "critical": Severity.CRITICAL,
        "info": Severity.INFO,
    }.get(tokens.get("severity", ""), Severity.WARNING)
    labels = {
        "alertname": alarm.alarm_name,
        "aws_account": alarm.account_id,
        "region": alarm.region,
        "environment": environment,
    }
    if alarm.trigger.metric_name:
        labels["metric"] = alarm.trigger.metric_name
    if alarm.trigger.namespace:
        labels["metric_namespace"] = alarm.trigger.namespace
    for dim in alarm.trigger.dimensions:
        labels[f"dim_{dim.name}"] = dim.value
    annotations = {"reason": alarm.reason}
    if alarm.trigger.threshold is not None:
        annotations["threshold"] = str(alarm.trigger.threshold)
    return Alert(
        source=AlertSource.CLOUDWATCH,
        fingerprint=f"cw:{alarm.alarm_arn}"[:200],
        name=alarm.alarm_name,
        status=status,
        severity=severity,
        summary=(alarm.alarm_description or alarm.alarm_name)[:2000],
        description=alarm.reason[:8000],
        labels=labels,
        annotations=annotations,
        starts_at=alarm.state_change_time,
        ends_at=alarm.state_change_time if status is AlertStatus.RESOLVED else None,
        target=_target(alarm, environment),
        payload_digest=content_digest(raw),
        received_at=received_at,
    )
