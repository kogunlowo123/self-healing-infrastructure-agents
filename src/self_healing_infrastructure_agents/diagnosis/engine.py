"""Deterministic diagnosis: playbook selection, evidence, hypothesis ranking, action."""

from __future__ import annotations

from typing import Any

from agentic_core.policy import Condition

from self_healing_infrastructure_agents.diagnosis.evidence import EvidenceCollector
from self_healing_infrastructure_agents.diagnosis.narrator import IncidentNarrator
from self_healing_infrastructure_agents.diagnosis.playbooks import (
    ActionTemplate,
    HypothesisSpec,
    Playbook,
    PlaybookSet,
)
from self_healing_infrastructure_agents.domain.models import (
    ActionKind,
    ActionSpec,
    Diagnosis,
    Evidence,
    Hypothesis,
    Incident,
    Target,
)
from self_healing_infrastructure_agents.domain.ports import Clock


def _describe(condition: Condition, facts: dict[str, Any]) -> str:
    key = condition.attribute.split(".", 1)[-1]
    actual = facts.get("resource", {}).get(key, "missing")
    return f"{key}={actual} ({condition.operator.value} {condition.value})"


class DiagnosisEngine:
    def __init__(
        self,
        playbooks: PlaybookSet,
        collector: EvidenceCollector,
        clock: Clock,
        narrator: IncidentNarrator | None = None,
    ) -> None:
        self._playbooks = playbooks
        self._collector = collector
        self._clock = clock
        self._narrator = narrator

    @property
    def playbooks(self) -> PlaybookSet:
        return self._playbooks

    async def diagnose(self, incident: Incident) -> Diagnosis:
        alert = incident.alerts[-1]
        playbook = self._playbooks.select(alert)
        if playbook is None:
            return self._escalation(
                None,
                Evidence(collected_at=self._clock.now()),
                f"No playbook covers alert {alert.name}; a human must triage it.",
            )
        target = incident.target
        if target is None:
            return self._escalation(
                playbook,
                Evidence(collected_at=self._clock.now()),
                f"{playbook.title}: alert labels do not identify a remediation target.",
            )
        evidence = await self._collector.collect(playbook.collectors, target, alert)
        diagnosis = self._evaluate(playbook, target, evidence)
        if self._narrator is not None:
            narrative = await self._narrator.narrate(incident, diagnosis)
            diagnosis = diagnosis.model_copy(update={"narrative": narrative.text})
        return diagnosis

    def _escalation(self, playbook: Playbook | None, evidence: Evidence, summary: str) -> Diagnosis:
        return Diagnosis(
            playbook_id=playbook.id if playbook else None,
            playbook_version=self._playbooks.version if playbook else None,
            evidence=evidence,
            summary=summary,
            escalate=True,
        )

    def _evaluate(self, playbook: Playbook, target: Target, evidence: Evidence) -> Diagnosis:
        facts = {"resource": evidence.facts}
        ranked: list[Hypothesis] = []
        notes: dict[str, str | None] = {}
        for spec in playbook.hypotheses:
            if not spec.holds(facts):
                continue
            action, problem = self._action(spec, target, evidence.facts)
            rationale = tuple(_describe(c, facts) for c in spec.when) + tuple(
                f"supporting: {_describe(c, facts)}" for c in spec.supporting if c.evaluate(facts)
            )
            if problem:
                rationale = (*rationale, problem)
            ranked.append(
                Hypothesis(
                    id=spec.id,
                    title=spec.title,
                    confidence=spec.score(facts),
                    rationale=rationale,
                    action=action,
                )
            )
            notes[spec.id] = spec.escalation or problem
        ranked.sort(key=lambda h: h.confidence, reverse=True)

        selected = ranked[0] if ranked and ranked[0].confidence >= playbook.min_confidence else None
        if selected is None:
            summary = (
                f"{playbook.title}: no hypothesis reached confidence {playbook.min_confidence}"
                + (f" ({len(evidence.errors)} evidence errors)" if evidence.errors else "")
                + "; escalating to a human."
            )
            return Diagnosis(
                playbook_id=playbook.id,
                playbook_version=self._playbooks.version,
                hypotheses=tuple(ranked),
                evidence=evidence,
                summary=summary,
                escalate=True,
            )
        if selected.action is None:
            note = notes.get(selected.id) or "no automated remediation exists for this cause"
            summary = f"{playbook.title}: {selected.title} ({selected.confidence}). {note}."
            escalate = True
        else:
            summary = (
                f"{playbook.title}: {selected.title} ({selected.confidence}). "
                f"Recommended {selected.action.kind.value} on {target.ref}."
            )
            escalate = False
        return Diagnosis(
            playbook_id=playbook.id,
            playbook_version=self._playbooks.version,
            hypotheses=tuple(ranked),
            selected=selected,
            evidence=evidence,
            summary=summary,
            escalate=escalate,
        )

    @staticmethod
    def _action(
        spec: HypothesisSpec, target: Target, facts: dict[str, Any]
    ) -> tuple[ActionSpec | None, str | None]:
        template: ActionTemplate | None = spec.action
        if template is None:
            return None, None
        if template.kind.target_kind is not target.kind:
            return None, f"action {template.kind.value} does not apply to {target.kind.value}"
        replicas: int | None = None
        if template.kind is ActionKind.SCALE_DEPLOYMENT:
            if template.scale is None:
                return None, "scale action without a scale strategy"
            current, utilization = facts.get("replicas"), facts.get("utilization")
            if not isinstance(current, int) or not isinstance(utilization, float):
                return None, "replica count or utilization unavailable"
            replicas = template.scale.desired(current, utilization)
            if replicas is None:
                return None, "scaling out cannot bring utilization under target"
        return (
            ActionSpec(
                kind=template.kind,
                target=target,
                replicas=replicas,
                reason=f"playbook hypothesis {spec.id}: {spec.title}",
            ),
            None,
        )
