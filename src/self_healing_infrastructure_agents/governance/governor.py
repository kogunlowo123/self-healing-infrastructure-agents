"""Policy validation of remediation actions.

The versioned ABAC policy (``policies/remediation.yaml``, evaluated by the
agentic-core PolicyEngine) decides allow / require_approval / deny. A small
set of invariants is enforced in code on top of the policy so that a policy
edit cannot remove them:

* Terraform plans that delete or replace a stateful resource are denied.
* Errored or non-applyable Terraform plans are denied.
* Live Terraform applies always need at least one human approval.
* Live actions in production always need at least one human approval.
* CRITICAL-risk actions need two distinct approvers (two-person rule).
* If a fact the policy relies on could not be collected, the action is
  denied rather than evaluated on partial information.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from agentic_core.domain.classification import Decision, RiskLevel
from agentic_core.policy import PolicyEngine, PolicyRequest, Resource, Subject
from pydantic import BaseModel, ConfigDict

from self_healing_infrastructure_agents.domain.models import (
    ActionKind,
    ActionSpec,
    ExecutionMode,
    PlanAnalysis,
    PolicyOutcome,
    Principal,
    expand_scopes,
)
from self_healing_infrastructure_agents.governance.change_windows import ChangeCalendar

_BASE_RISK = {
    ActionKind.RESTART_DEPLOYMENT: RiskLevel.MODERATE,
    ActionKind.SCALE_DEPLOYMENT: RiskLevel.LOW,
    ActionKind.ROLLOUT_UNDO: RiskLevel.HIGH,
    ActionKind.CORDON_NODE: RiskLevel.MODERATE,
    ActionKind.UNCORDON_NODE: RiskLevel.LOW,
    ActionKind.TERRAFORM_APPLY: RiskLevel.MODERATE,
}

RESOURCE_TYPES = {
    ActionKind.RESTART_DEPLOYMENT: "k8s:deployment",
    ActionKind.SCALE_DEPLOYMENT: "k8s:deployment",
    ActionKind.ROLLOUT_UNDO: "k8s:deployment",
    ActionKind.CORDON_NODE: "k8s:node",
    ActionKind.UNCORDON_NODE: "k8s:node",
    ActionKind.TERRAFORM_APPLY: "terraform:stack",
}

# Facts each action's policy rules depend on; absent facts deny the action.
REQUIRED_FACTS = {
    ActionKind.SCALE_DEPLOYMENT: ("replicas_current", "replicas_target"),
    ActionKind.CORDON_NODE: ("ready_nodes_after", "ready_ratio_after"),
    ActionKind.TERRAFORM_APPLY: ("stateful_destroys", "risk_score"),
}

PRODUCTION_ENVIRONMENTS = frozenset({"production", "prod"})


class Verdict(BaseModel):
    model_config = ConfigDict(frozen=True)

    outcome: PolicyOutcome
    risk: RiskLevel
    required_approvals: int


def terraform_facts(analysis: PlanAnalysis, action: ActionSpec) -> dict[str, Any]:
    return {
        "stateful_destroys": len(analysis.stateful_deletes) + len(analysis.stateful_replacements),
        "destructive_count": len(analysis.destructive),
        "security_changes": len(analysis.security_changes),
        "protection_disabled": len(analysis.protection_disabled),
        "blast_radius": len(analysis.blast_radius),
        "risk_score": analysis.risk_score,
        "errored": analysis.errored,
        "applyable": analysis.applyable,
        "has_rollback_stack": action.rollback_stack is not None,
    }


class RemediationGovernor:
    def __init__(
        self,
        policy: PolicyEngine,
        calendar: ChangeCalendar,
        *,
        protected_namespaces: frozenset[str],
    ) -> None:
        self._policy = policy
        self._calendar = calendar
        self._protected = protected_namespaces

    @property
    def policy(self) -> PolicyEngine:
        return self._policy

    @property
    def calendar(self) -> ChangeCalendar:
        return self._calendar

    def assess_risk(self, action: ActionSpec, analysis: PlanAnalysis | None) -> RiskLevel:
        risk = _BASE_RISK[action.kind]
        if analysis is not None:
            risk = max(risk, analysis.risk)
        if action.target.environment in PRODUCTION_ENVIRONMENTS:
            risk = RiskLevel(min(int(risk) + 1, int(RiskLevel.CRITICAL)))
        return risk

    def evaluate(
        self,
        *,
        principal: Principal,
        action: ActionSpec,
        mode: ExecutionMode,
        facts: dict[str, Any],
        at: datetime,
        analysis: PlanAnalysis | None = None,
    ) -> Verdict:
        target = action.target
        window = self._calendar.status(target.environment, at)
        resource_facts: dict[str, Any] = {
            "environment": target.environment,
            "kind": target.kind.value,
            "name": target.name,
            "namespace": target.namespace,
            "cluster": target.cluster,
            "protected_namespace": bool(target.namespace and target.namespace in self._protected),
            **facts,
        }
        if analysis is not None:
            resource_facts.update(terraform_facts(analysis, action))
        risk = self.assess_risk(action, analysis)
        request = PolicyRequest(
            subject=Subject(
                id=principal.subject,
                kind=principal.kind.value,
                roles=principal.roles,
                attributes={"scopes": sorted(expand_scopes(principal.scopes))},
            ),
            action=action.kind.value,
            resource=Resource(
                type=RESOURCE_TYPES[action.kind], id=target.ref, attributes=resource_facts
            ),
            risk=risk,
            environment={
                "mode": mode.value,
                "in_change_window": window.open,
                "freeze": window.frozen,
            },
        )
        decision = self._policy.evaluate(request)
        outcome_decision = decision.decision
        matched = list(decision.matched_rules)
        reasons = [decision.reason]
        if not window.open:
            reasons.append(window.reason)

        missing = [f for f in REQUIRED_FACTS.get(action.kind, ()) if f not in resource_facts]
        if missing:
            outcome_decision = Decision.DENY
            matched.append("invariant:facts-unavailable")
            reasons.append(f"required facts unavailable: {missing}")
        if analysis is not None:
            if terraform_facts(analysis, action)["stateful_destroys"]:
                outcome_decision = Decision.DENY
                matched.append("invariant:no-stateful-destroy")
                reasons.append("plan deletes or replaces a stateful resource")
            if analysis.errored or not analysis.applyable:
                outcome_decision = Decision.DENY
                matched.append("invariant:applyable-plan")
                reasons.append("plan is errored or not applyable")

        required = 0
        if outcome_decision is not Decision.DENY:
            live = mode is ExecutionMode.LIVE
            floor = (
                live
                and (
                    action.kind is ActionKind.TERRAFORM_APPLY
                    or target.environment in PRODUCTION_ENVIRONMENTS
                )
            ) or principal.requires_approval
            if outcome_decision is Decision.REQUIRE_APPROVAL or floor:
                if outcome_decision is Decision.ALLOW:
                    matched.append("invariant:approval-floor")
                    reasons.append("live change requires human approval")
                outcome_decision = Decision.REQUIRE_APPROVAL
                required = 2 if risk is RiskLevel.CRITICAL else 1

        outcome = PolicyOutcome(
            decision=outcome_decision,
            matched_rules=tuple(matched),
            policy_name=decision.policy_name,
            policy_version=decision.policy_version,
            policy_digest=decision.policy_digest,
            reason="; ".join(reasons),
            evaluated_at=at,
            facts={
                "resource": resource_facts,
                "environment": dict(request.environment),
                "risk": int(risk),
            },
        )
        return Verdict(outcome=outcome, risk=risk, required_approvals=required)
