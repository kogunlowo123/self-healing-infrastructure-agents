"""Latency budgets for hot paths. Loose enough for shared CI runners."""

from __future__ import annotations

import time
from typing import Any

import pytest
from agentic_core.policy import PolicyEngine, PolicySet

from self_healing_infrastructure_agents.analysis.terraform_plan import analyze_plan
from self_healing_infrastructure_agents.domain.models import ExecutionMode
from self_healing_infrastructure_agents.governance.change_windows import ChangeCalendar
from self_healing_infrastructure_agents.governance.governor import RemediationGovernor
from self_healing_infrastructure_agents.runtime.container import Container
from tests.conftest import ROOT, START
from tests.unit.test_governor import AGENT, deployment_action
from tests.unit.test_models import make_alert

pytestmark = pytest.mark.performance


def large_plan(resources: int) -> dict[str, Any]:
    changes = []
    config = []
    for i in range(resources):
        address = f"aws_instance.web{i}"
        changes.append(
            {
                "address": address,
                "type": "aws_instance",
                "mode": "managed",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {
                    "actions": ["update"] if i % 3 else ["no-op"],
                    "before": {"instance_type": "m6i.large", "tags": {"n": str(i)}},
                    "after": {"instance_type": "m6i.xlarge", "tags": {"n": str(i)}},
                },
            }
        )
        refs = [f"aws_instance.web{i - 1}.id"] if i else ["aws_vpc.main.id"]
        config.append({"address": address, "expressions": {"subnet": {"references": refs}}})
    config.append({"address": "aws_vpc.main", "expressions": {}})
    return {
        "format_version": "1.2",
        "terraform_version": "1.7.5",
        "resource_changes": changes,
        "configuration": {"root_module": {"resources": config}},
    }


def test_large_plan_analysis_budget() -> None:
    plan = large_plan(3000)
    started = time.perf_counter()
    analysis = analyze_plan(plan)
    elapsed = time.perf_counter() - started
    # A chain: web1 is the first changed instance, everything after it depends on it.
    assert len(analysis.blast_radius) == 2999
    assert elapsed < 3.0


def test_policy_evaluation_budget() -> None:
    governor = RemediationGovernor(
        PolicyEngine(PolicySet.from_file(ROOT / "policies" / "remediation.yaml")),
        ChangeCalendar.from_file(ROOT / "policies" / "change-windows.yaml"),
        protected_namespaces=frozenset({"kube-system"}),
    )
    action = deployment_action(environment="production")
    started = time.perf_counter()
    for _ in range(500):
        governor.evaluate(
            principal=AGENT, action=action, mode=ExecutionMode.LIVE, facts={}, at=START
        )
    per_call_ms = (time.perf_counter() - started) * 1000 / 500
    assert per_call_ms < 10


async def test_ingest_repeat_budget(container: Container) -> None:
    await container.incidents.ingest([make_alert(name="Unmatched")], received_by="perf")
    started = time.perf_counter()
    for _ in range(50):
        await container.incidents.ingest([make_alert(name="Unmatched")], received_by="perf")
    per_alert_ms = (time.perf_counter() - started) * 1000 / 50
    assert per_alert_ms < 250
