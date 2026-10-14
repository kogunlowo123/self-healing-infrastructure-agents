# syntax=docker/dockerfile:1.7

# Terraform CLI for terraform:apply remediations, built from the pinned release
# tag with a patched Go toolchain: the upstream release binary is linked
# against a Go standard library with known, fixed vulnerabilities. The tag is
# verified against its commit SHA and module downloads against go.sum and the
# Go checksum database.
FROM golang:1.27.1-trixie AS terraform
ARG TERRAFORM_VERSION=1.16.6
ARG TERRAFORM_COMMIT=7b8f1669b95119ac6021e05c9d10eae7cf75f60b
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
RUN git clone --depth 1 --branch "v${TERRAFORM_VERSION}" https://github.com/hashicorp/terraform.git /src/terraform  && test "$(git -C /src/terraform rev-parse HEAD)" = "${TERRAFORM_COMMIT}"
WORKDIR /src/terraform
RUN go build -trimpath -ldflags "-s -w -X github.com/hashicorp/terraform/version.dev=no" -o /opt/terraform/terraform .  && /opt/terraform/terraform version

FROM python:3.12.15-slim-trixie AS build
COPY --from=ghcr.io/astral-sh/uv:0.12.7 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
RUN apt-get update  && apt-get install -y --no-install-recommends git ca-certificates  && rm -rf /var/lib/apt/lists/*

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
COPY --from=terraform /opt/terraform/terraform /usr/local/bin/terraform
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
