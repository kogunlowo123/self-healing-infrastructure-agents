"""Runtime settings, read from HEAL_* environment variables.

Deployment-specific values have no defaults: the service refuses to start
until they are provided. Dry run is the default execution mode.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

from pydantic import Field, HttpUrl, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from self_healing_infrastructure_agents.domain.models import ExecutionMode

SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HEAL_", env_nested_delimiter="__")

    environment: str = "production"
    public_url: HttpUrl = Field(description="External URL of this service (A2A agent card)")
    database_url: str = Field(description="SQLAlchemy async URL, e.g. postgresql+asyncpg://...")
    default_alert_environment: str = Field(
        default="production",
        description="Environment assumed for alerts that carry no environment label",
    )

    audit_log_path: Path = Path("/var/lib/self-healing-agents/audit/audit.jsonl")
    audit_key_file: Path | None = Field(default=None, description="Ed25519 PEM audit signing key")
    dev_ephemeral_keys: bool = Field(
        default=False,
        description="Generate an in-memory audit key at start-up. Refused in production.",
    )

    execution_mode: ExecutionMode = ExecutionMode.DRY_RUN
    auto_propose: bool = True
    auto_execute: bool = True
    plan_ttl_seconds: int = Field(default=3600, ge=300, le=86_400)
    rollout_timeout_seconds: int = Field(default=600, ge=30, le=3600)
    poll_interval_seconds: float = Field(default=5.0, gt=0, le=60)
    plan_sweep_interval_seconds: float = Field(default=60.0, gt=0)

    # Human operators and approvers (enterprise OIDC).
    operator_issuer: str
    operator_audience: str
    operator_jwks_url: str
    operator_roles_claim: str = "roles"

    # Agent callers and this service's own identity (agent identity fabric).
    agent_id: str = Field(description="SPIFFE ID this service is registered under")
    fabric_url: str | None = None
    workload_token_file: Path = SA_DIR / "token"
    agent_issuer: str | None = Field(
        default=None, description="Fabric issuer for local verification when fabric_url is unset"
    )
    agent_jwks_url: str | None = None
    agent_audience: str = "agent-platform"
    agent_scopes: list[str] = Field(
        default_factory=lambda: [
            "remediation:propose",
            "remediation:dry-run",
            "remediation:execute",
        ]
    )

    # Alert sources.
    alertmanager_token: SecretStr | None = Field(
        default=None, description="Bearer token Alertmanager presents (http_config.authorization)"
    )
    sns_topic_arns: list[str] = Field(default_factory=list)

    # Kubernetes API (in-cluster defaults).
    kube_api_url: str = "https://kubernetes.default.svc"
    kube_token_file: Path = SA_DIR / "token"
    kube_ca_file: Path = SA_DIR / "ca.crt"
    protected_namespaces: list[str] = Field(
        default_factory=lambda: ["kube-system", "kube-public", "kube-node-lease"]
    )

    # Terraform.
    terraform_root: Path = Path("/var/lib/self-healing-agents/stacks")
    terraform_binary: str = "terraform"
    terraform_timeout_seconds: int = Field(default=1800, ge=60, le=7200)

    # Versioned policy and playbooks.
    policy_file: Path = Path("policies/remediation.yaml")
    access_policy_file: Path = Path("policies/agent-access.yaml")
    playbooks_file: Path = Path("policies/diagnosis-playbooks.yaml")
    change_calendar_file: Path = Path("policies/change-windows.yaml")
    providers_file: Path | None = Field(
        default=None, description="configs/providers.yaml enables the advisory incident narrator"
    )

    mcp_allowed_hosts: list[str] = Field(
        default_factory=list, description="Host headers accepted by /mcp; defaults to public_url"
    )
    log_level: str = "INFO"
    otlp_endpoint: str | None = None

    @model_validator(mode="after")
    def _consistent(self) -> Settings:
        if self.dev_ephemeral_keys:
            if self.environment == "production":
                raise ValueError("dev_ephemeral_keys cannot be used in production")
        elif self.audit_key_file is None:
            raise ValueError("HEAL_AUDIT_KEY_FILE is required unless dev_ephemeral_keys is set")
        if self.fabric_url is None and not (self.agent_issuer and self.agent_jwks_url):
            raise ValueError(
                "agent authorization needs HEAL_FABRIC_URL or HEAL_AGENT_ISSUER + "
                "HEAL_AGENT_JWKS_URL; there is no allow-all mode"
            )
        if not self.agent_id.startswith("spiffe://"):
            raise ValueError("HEAL_AGENT_ID must be the SPIFFE ID registered in the fabric")
        return self

    @property
    def public_url_str(self) -> str:
        return str(self.public_url).rstrip("/")

    @property
    def allowed_hosts(self) -> list[str]:
        if self.mcp_allowed_hosts:
            return list(self.mcp_allowed_hosts)
        parsed = urlparse(self.public_url_str)
        return [h for h in {parsed.netloc, parsed.hostname or ""} if h]
