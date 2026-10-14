.PHONY: install format lint typecheck security contracts test integration check helm terraform audit-deps image run clean

CHART := deployments/helm/self-healing-infrastructure-agents

install:
	uv sync

format:
	uv run black src tests
	uv run ruff check src tests --fix

lint:
	uv run ruff check src tests
	uv run black --check src tests

typecheck:
	uv run mypy

security:
	uv run python -m bandit -q -r src -c pyproject.toml

contracts:
	uv run python -m self_healing_infrastructure_agents.contracts --check

test:
	uv run pytest

integration:
	uv run pytest tests/integration -m integration --no-cov

check: lint typecheck security contracts test

helm:
	helm lint $(CHART) -f $(CHART)/ci/test-values.yaml
	helm template heal $(CHART) -f $(CHART)/ci/test-values.yaml > rendered.yaml
	@if helm template heal $(CHART) > /dev/null 2>&1; then echo "chart rendered without required values"; exit 1; fi

terraform:
	terraform fmt -recursive -check deployments/terraform
	for c in aws azure gcp; do terraform -chdir=deployments/terraform/$$c init -backend=false -input=false && terraform -chdir=deployments/terraform/$$c validate; done

audit-deps:
	uv export --frozen --no-dev --no-emit-project --no-hashes > requirements.audit.txt
	uvx pip-audit -r requirements.audit.txt --strict
	rm requirements.audit.txt

image:
	docker build -t self-healing-infrastructure-agents:dev .

run:
	docker compose up --build

clean:
	rm -rf dist build .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml rendered.yaml
