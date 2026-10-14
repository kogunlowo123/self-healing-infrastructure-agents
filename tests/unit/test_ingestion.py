"""Alertmanager and CloudWatch parsing and target derivation."""

from __future__ import annotations

import json

import pytest

from self_healing_infrastructure_agents.domain.errors import HealingError
from self_healing_infrastructure_agents.domain.models import (
    AlertSource,
    AlertStatus,
    Severity,
    TargetKind,
)
from self_healing_infrastructure_agents.ingestion.alertmanager import (
    AlertmanagerWebhook,
    parse_alertmanager,
)
from self_healing_infrastructure_agents.ingestion.cloudwatch import (
    alert_from_alarm,
    parse_alarm_message,
)
from self_healing_infrastructure_agents.ingestion.targets import (
    deployment_from_pod,
    target_from_labels,
)
from tests.conftest import START, load


def parse(document: dict[str, object]) -> list:  # type: ignore[type-arg]
    raw = json.dumps(document).encode()
    return parse_alertmanager(
        AlertmanagerWebhook.model_validate(document),
        raw,
        received_at=START,
        default_environment="production",
    )


class TestAlertmanager:
    def test_recorded_crashloop_webhook(self) -> None:
        [alert] = parse(load("alerts/alertmanager-crashloop.json"))
        assert alert.source is AlertSource.ALERTMANAGER
        assert alert.fingerprint == "am:8f2b7c1d9e4a6b30"
        assert alert.name == "KubePodCrashLooping"
        assert alert.status is AlertStatus.FIRING
        assert alert.severity is Severity.WARNING
        assert alert.ends_at is None  # Go zero time means "no end"
        assert alert.summary == "Pod is crash looping."
        assert alert.target is not None
        assert alert.target.kind is TargetKind.DEPLOYMENT
        assert alert.target.ref == "eks-prod-use1:deployment/payments/checkout"
        assert alert.target.environment == "staging"
        assert alert.payload_digest.startswith("sha256:")

    def test_alert_labels_override_common_labels(self) -> None:
        document = load("alerts/alertmanager-crashloop.json")
        document["alerts"][0]["labels"]["severity"] = "critical"
        document["alerts"][0]["endsAt"] = "2026-10-14T14:10:00Z"
        document["alerts"][0]["status"] = "resolved"
        [alert] = parse(document)
        assert alert.severity is Severity.CRITICAL
        assert alert.status is AlertStatus.RESOLVED
        assert alert.ends_at is not None

    @pytest.mark.parametrize(
        ("label", "expected"),
        [("page", Severity.CRITICAL), ("info", Severity.INFO), ("", Severity.WARNING)],
    )
    def test_severity_mapping(self, label: str, expected: Severity) -> None:
        document = load("alerts/alertmanager-crashloop.json")
        document["commonLabels"]["severity"] = label
        assert parse(document)[0].severity is expected

    def test_rejects_other_payload_versions(self) -> None:
        document = load("alerts/alertmanager-crashloop.json")
        document["version"] = "3"
        with pytest.raises(ValueError, match="pattern"):
            AlertmanagerWebhook.model_validate(document)


class TestTargets:
    def test_deployment_from_pod_name(self) -> None:
        assert deployment_from_pod("checkout-7c9d8b6f5d-x2kq9") == "checkout"
        assert deployment_from_pod("api-gateway-5d4f7b9c8-abcde") == "api-gateway"
        assert deployment_from_pod("statefulset-0") is None

    def test_node_exporter_instance(self) -> None:
        target = target_from_labels(
            {"job": "node-exporter", "instance": "ip-10-0-1-5.ec2.internal:9100", "env": "prod"},
            default_environment="production",
        )
        assert target is not None
        assert target.kind is TargetKind.NODE
        assert target.name == "ip-10-0-1-5.ec2.internal"
        assert target.environment == "prod"

    def test_invalid_labels_yield_no_target(self) -> None:
        assert (
            target_from_labels({"namespace": "Bad NS", "deployment": "x"}, default_environment="p")
            is None
        )
        assert target_from_labels({"node": "UPPER_case"}, default_environment="p") is None
        assert target_from_labels({"alertname": "Watchdog"}, default_environment="p") is None

    def test_falls_back_to_node_when_deployment_invalid(self) -> None:
        target = target_from_labels(
            {"namespace": "Bad NS", "deployment": "x", "node": "node-a"}, default_environment="p"
        )
        assert target is not None
        assert target.kind is TargetKind.NODE


class TestCloudWatch:
    def test_recorded_rds_alarm(self) -> None:
        document = load("alerts/cloudwatch-rds-storage.json")
        raw = json.dumps(document).encode()
        alert = alert_from_alarm(
            parse_alarm_message(json.dumps(document)),
            raw,
            received_at=START,
            default_environment="staging",
        )
        assert alert is not None
        assert alert.source is AlertSource.CLOUDWATCH
        assert alert.status is AlertStatus.FIRING
        assert alert.severity is Severity.CRITICAL
        assert alert.labels["environment"] == "production"
        assert alert.labels["dim_DBInstanceIdentifier"] == "orders"
        assert alert.annotations["threshold"] == "10737418240.0"
        assert alert.target is not None
        assert alert.target.kind is TargetKind.CLOUD_RESOURCE
        assert alert.target.name == "AWS/RDS/DBInstanceIdentifier=orders"

    def test_ok_resolves_and_insufficient_data_is_ignored(self) -> None:
        document = load("alerts/cloudwatch-rds-storage.json")
        document["NewStateValue"] = "OK"
        alarm = parse_alarm_message(json.dumps(document))
        alert = alert_from_alarm(alarm, b"{}", received_at=START, default_environment="p")
        assert alert is not None
        assert alert.status is AlertStatus.RESOLVED
        assert alert.ends_at == alarm.state_change_time
        document["NewStateValue"] = "INSUFFICIENT_DATA"
        alarm = parse_alarm_message(json.dumps(document))
        assert alert_from_alarm(alarm, b"{}", received_at=START, default_environment="p") is None

    @pytest.mark.parametrize(
        ("dimensions", "kind", "name"),
        [
            (
                [{"name": "ClusterName", "value": "eks-1"}, {"name": "NodeName", "value": "ip-1"}],
                TargetKind.NODE,
                "ip-1",
            ),
            (
                [
                    {"name": "ClusterName", "value": "eks-1"},
                    {"name": "Namespace", "value": "payments"},
                    {"name": "PodName", "value": "checkout"},
                ],
                TargetKind.DEPLOYMENT,
                "checkout",
            ),
            (
                [
                    {"name": "ClusterName", "value": "eks-1"},
                    {"name": "Namespace", "value": "Bad NS"},
                    {"name": "Service", "value": "checkout"},
                ],
                None,
                None,
            ),
            ([], None, None),
        ],
    )
    def test_container_insights_dimensions(
        self, dimensions: list[dict[str, str]], kind: TargetKind | None, name: str | None
    ) -> None:
        document = load("alerts/cloudwatch-rds-storage.json")
        document["Trigger"]["Dimensions"] = dimensions
        document["AlarmDescription"] = None
        alert = alert_from_alarm(
            parse_alarm_message(json.dumps(document)),
            b"{}",
            received_at=START,
            default_environment="staging",
        )
        assert alert is not None
        assert alert.severity is Severity.WARNING
        if kind is None:
            assert alert.target is None
        else:
            assert alert.target is not None
            assert (alert.target.kind, alert.target.name) == (kind, name)

    def test_rejects_non_alarm_messages(self) -> None:
        with pytest.raises(HealingError):
            parse_alarm_message("not json")
        with pytest.raises(HealingError):
            parse_alarm_message(json.dumps({"hello": "world"}))

    def test_info_severity_token(self) -> None:
        document = load("alerts/cloudwatch-rds-storage.json")
        document["AlarmDescription"] = "severity:info env:dev"
        document["Trigger"]["Threshold"] = None
        alert = alert_from_alarm(
            parse_alarm_message(json.dumps(document)),
            b"{}",
            received_at=START,
            default_environment="staging",
        )
        assert alert is not None
        assert alert.severity is Severity.INFO
        assert alert.labels["environment"] == "dev"
        assert "threshold" not in alert.annotations
