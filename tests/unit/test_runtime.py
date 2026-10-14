"""Contracts, settings validation, container wiring and shipped configuration."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import yaml
from agentic_core.models.factory import ProvidersConfig, env_references
from agentic_core.policy import PolicySet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from self_healing_infrastructure_agents.contracts import main
from self_healing_infrastructure_agents.diagnosis.playbooks import PlaybookSet
from self_healing_infrastructure_agents.governance.change_windows import ChangeCalendar
from self_healing_infrastructure_agents.runtime.container import build_container
from self_healing_infrastructure_agents.security.callers import FabricAgentAuthorizer
from tests.conftest import (
    PUBLIC_URL,
    ROOT,
    FakeClock,
    FakeCluster,
    FakeIdp,
    FakeTerraform,
    make_settings,
    wired,
)


class TestContracts:
    def test_committed_contracts_are_current(self) -> None:
        assert main(["--check"], root=ROOT) == 0

    def test_export_and_check_round_trip(self, tmp_path: Path) -> None:
        assert main(["--check"], root=tmp_path) == 1
        assert main([], root=tmp_path) == 0
        assert main(["--check"], root=tmp_path) == 0
        assert (tmp_path / "schemas" / "remediation-plan.response.schema.json").is_file()
        openapi = json.loads((tmp_path / "docs" / "api" / "openapi.json").read_text("utf-8"))
        assert "/v1/remediations/{plan_id}/decision" in openapi["paths"]


class TestSettings:
    def test_production_refuses_ephemeral_keys(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="production"):
            make_settings(tmp_path, environment="production")

    def test_audit_key_required(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="AUDIT_KEY_FILE"):
            make_settings(tmp_path, dev_ephemeral_keys=False)

    def test_no_allow_all_mode(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="no allow-all"):
            make_settings(tmp_path, agent_issuer=None)

    def test_agent_id_must_be_spiffe(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="SPIFFE"):
            make_settings(tmp_path, agent_id="self-healer")

    def test_allowed_hosts(self, tmp_path: Path) -> None:
        settings = make_settings(tmp_path, public_url="https://heal.corp.test:8443/")
        assert set(settings.allowed_hosts) == {"heal.corp.test:8443", "heal.corp.test"}
        assert settings.public_url_str == "https://heal.corp.test:8443"
        explicit = make_settings(tmp_path, mcp_allowed_hosts=["mcp.corp.test"])
        assert explicit.allowed_hosts == ["mcp.corp.test"]


class TestContainer:
    async def test_persistent_audit_key_and_fabric_mode(
        self,
        tmp_path: Path,
        cluster: FakeCluster,
        terraform: FakeTerraform,
        clock: FakeClock,
        operator_idp: FakeIdp,
        agent_idp: FakeIdp,
    ) -> None:
        key_file = tmp_path / "audit-2026-10.pem"
        key_file.write_bytes(
            Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        settings = make_settings(
            tmp_path,
            dev_ephemeral_keys=False,
            audit_key_file=key_file,
            fabric_url="https://identity.corp.test",
            agent_issuer=None,
            agent_jwks_url=None,
        )
        container = await wired(
            settings,
            cluster=cluster,
            terraform=terraform,
            clock=clock,
            operator_idp=operator_idp,
            agent_idp=agent_idp,
        )
        try:
            assert container.audit._key_id == "audit-2026-10"
            assert isinstance(container.callers._agents, FabricAgentAuthorizer)
            assert container.remediation._fabric is not None
        finally:
            await container.aclose()

    async def test_rejects_non_ed25519_audit_key(self, tmp_path: Path) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec

        key_file = tmp_path / "audit.pem"
        key_file.write_bytes(
            ec.generate_private_key(ec.SECP256R1()).private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        settings = make_settings(tmp_path, dev_ephemeral_keys=False, audit_key_file=key_file)
        with pytest.raises(ValueError, match="Ed25519"):
            await build_container(settings, cluster=FakeCluster(), terraform=FakeTerraform())

    async def test_default_adapters_and_narrator(self, tmp_path: Path) -> None:
        providers = tmp_path / "providers.yaml"
        providers.write_text(
            yaml.safe_dump(
                {
                    "providers": [
                        {
                            "kind": "openai_compatible",
                            "base_url": "http://llm.test",
                            "auth": "none",
                            "profile": {
                                "name": "selfhosted",
                                "model": "m",
                                "max_classification": 3,
                                "tasks": ["summarize"],
                            },
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        settings = make_settings(tmp_path, providers_file=providers)
        transport = httpx.MockTransport(lambda _: httpx.Response(200, json={}))
        container = await build_container(settings, model_transport=transport)
        try:
            assert container.incidents._engine._narrator is not None
            assert container.settings.public_url_str == PUBLIC_URL
        finally:
            await container.aclose()

    async def test_default_kubernetes_client_trusts_cluster_ca(self, tmp_path: Path) -> None:
        from datetime import UTC, datetime, timedelta

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        from self_healing_infrastructure_agents.runtime.container import _kubernetes

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "kubernetes")])
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        ca = tmp_path / "ca.crt"
        ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        client, http = _kubernetes(make_settings(tmp_path, kube_ca_file=ca))
        try:
            assert str(http.base_url) == "https://kubernetes.default.svc"
            assert client is not None
        finally:
            await http.aclose()


class TestShippedConfiguration:
    def test_policies_parse_with_unique_rules(self) -> None:
        for name in ("remediation", "agent-access"):
            policy = PolicySet.from_file(ROOT / "policies" / f"{name}.yaml")
            assert policy.name == name
            assert policy.rules

    def test_playbooks_and_calendar(self) -> None:
        assert PlaybookSet.from_file(ROOT / "policies" / "diagnosis-playbooks.yaml").playbooks
        assert ChangeCalendar.from_file(ROOT / "policies" / "change-windows.yaml").windows

    def test_providers_config_resolves_from_environment(self) -> None:
        path = ROOT / "configs" / "providers.yaml"
        names = env_references(path.read_text(encoding="utf-8"))
        assert {"BEDROCK_MODEL_ID", "AWS_REGION"} <= names
        env = dict.fromkeys(names, "0.5")
        env.update(
            {
                "BEDROCK_MODEL_ID": "anthropic.claude-model-on-bedrock",
                "AWS_REGION": "us-east-1",
                "ANTHROPIC_MODEL": "claude-model",
                "ANTHROPIC_API_KEY": "configured-in-secret-store",
            }
        )
        config = ProvidersConfig.from_file(path, env=env)
        assert [p.profile.name for p in config.providers] == ["bedrock-claude", "claude"]
        with pytest.raises(ValueError, match="unset environment variables"):
            ProvidersConfig.from_file(path, env={})

    def test_prometheus_rules_reference_exported_metrics(self) -> None:
        rules = yaml.safe_load((ROOT / "configs" / "prometheus" / "alerts.yaml").read_text("utf-8"))
        exprs = " ".join(
            str(rule.get("expr", "")) for group in rules["groups"] for rule in group["rules"]
        )
        for metric in ("heal_http_request_duration_seconds", "heal_remediations_total"):
            assert metric in exprs
        dashboard = json.loads(
            (ROOT / "configs" / "grafana" / "self-healing-infrastructure-agents.json").read_text(
                "utf-8"
            )
        )
        assert dashboard["uid"] == "self-healing-infrastructure-agents"
