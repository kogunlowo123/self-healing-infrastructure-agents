# syntax=docker/dockerfile:1.7
FROM python:3.12.15-slim-trixie AS build
COPY --from=ghcr.io/astral-sh/uv:0.12.7 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Terraform CLI for terraform:apply remediations, pinned and checksum-verified.
ARG TERRAFORM_VERSION=1.16.6
ARG TERRAFORM_SHA256=38034b38d03096399a7a1264a14561a8029b2b496fd1f169452656e53968f1b7
RUN curl -sSfL -o /tmp/terraform.zip \
      "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" \
 && echo "${TERRAFORM_SHA256}  /tmp/terraform.zip" | sha256sum -c - \
 && python -m zipfile -e /tmp/terraform.zip /opt/terraform \
 && chmod 0755 /opt/terraform/terraform \
 && rm /tmp/terraform.zip

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12.15-slim-trixie AS runtime
RUN apt-get update  && apt-get upgrade -y --no-install-recommends  && rm -rf /var/lib/apt/lists/*  && groupadd --system --gid 10001 heal \
 && useradd --system --uid 10001 --gid heal --home-dir /nonexistent --shell /usr/sbin/nologin heal \
 && mkdir -p /var/lib/self-healing-agents/audit /var/lib/self-healing-agents/stacks \
 && chown -R 10001:10001 /var/lib/self-healing-agents
WORKDIR /app
COPY --from=build /opt/terraform/terraform /usr/local/bin/terraform
COPY --from=build --chown=10001:10001 /app/.venv /app/.venv
COPY --chown=10001:10001 policies ./policies
COPY --chown=10001:10001 configs/providers.yaml ./configs/providers.yaml
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HEAL_HOST=0.0.0.0 \
    HEAL_PORT=8080 \
    HEAL_POLICY_FILE=/app/policies/remediation.yaml \
    HEAL_ACCESS_POLICY_FILE=/app/policies/agent-access.yaml \
    HEAL_PLAYBOOKS_FILE=/app/policies/diagnosis-playbooks.yaml \
    HEAL_CHANGE_CALENDAR_FILE=/app/policies/change-windows.yaml \
    TF_PLUGIN_CACHE_DIR=/var/lib/self-healing-agents/stacks/.plugin-cache
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"]
ENTRYPOINT ["python", "-m", "self_healing_infrastructure_agents"]
