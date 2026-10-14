# Contributing

## Setup

```bash
uv sync
make check
```

## Requirements for every change

- `make check` passes: ruff, black, mypy `--strict`, bandit, contract drift, tests with at
  least 90% branch coverage.
- New behaviour has tests. Safety controls (policy, approvals, execution, rollback,
  ingestion verification) need adversarial cases in `tests/security` or `tests/chaos`.
- Changes to request or response models regenerate the published contracts:
  `uv run python -m self_healing_infrastructure_agents.contracts`.
- Changes to `policies/` keep the tests in `tests/unit/test_governor.py` and
  `tests/unit/test_diagnosis.py` meaningful; a policy change that loosens a control
  needs an ADR.
- Public API changes are recorded in `CHANGELOG.md`.
- Architecturally significant decisions get an ADR in `docs/architecture/adr/`.
- No credentials, customer data or real infrastructure identifiers in code, tests or
  fixtures. Use synthetic data and recorded wire shapes.

## Commit messages

Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
Breaking changes use `!` and a `BREAKING CHANGE:` footer.

## Review

Changes to `src/self_healing_infrastructure_agents/security`, `governance`,
`remediation`, `policies/` or `deployments/` need approval from a code owner
(see `CODEOWNERS`).
