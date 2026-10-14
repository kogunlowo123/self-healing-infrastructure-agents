"""Export published contracts: JSON Schemas for inputs/outputs and the OpenAPI document.

python -m self_healing_infrastructure_agents.contracts          # rewrite schemas/, docs/api/
python -m self_healing_infrastructure_agents.contracts --check  # exit 1 if files are stale
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from self_healing_infrastructure_agents.api.app import create_app
from self_healing_infrastructure_agents.api.schemas import (
    AnalyzePlanRequest,
    ApprovalRequest,
    ExecuteRequest,
    ProposeRemediation,
)
from self_healing_infrastructure_agents.application.incidents import IngestResult
from self_healing_infrastructure_agents.domain.models import (
    ActionSpec,
    Diagnosis,
    Incident,
    PlanAnalysis,
    RemediationPlan,
)
from self_healing_infrastructure_agents.ingestion.alertmanager import AlertmanagerWebhook
from self_healing_infrastructure_agents.ingestion.cloudwatch import CloudWatchAlarm
from self_healing_infrastructure_agents.security.sns import SnsEnvelope

BASE_ID = "https://github.com/kogunlowo123/self-healing-infrastructure-agents/schemas"

MODELS: dict[str, tuple[type[BaseModel], str]] = {
    "alertmanager-webhook.request": (AlertmanagerWebhook, "validation"),
    "sns-envelope.request": (SnsEnvelope, "validation"),
    "cloudwatch-alarm.message": (CloudWatchAlarm, "validation"),
    "ingest-result.response": (IngestResult, "serialization"),
    "action-spec": (ActionSpec, "validation"),
    "propose-remediation.request": (ProposeRemediation, "validation"),
    "approval.request": (ApprovalRequest, "validation"),
    "execute.request": (ExecuteRequest, "validation"),
    "analyze-plan.request": (AnalyzePlanRequest, "validation"),
    "plan-analysis.response": (PlanAnalysis, "serialization"),
    "diagnosis": (Diagnosis, "serialization"),
    "incident.response": (Incident, "serialization"),
    "remediation-plan.response": (RemediationPlan, "serialization"),
}


async def _no_container() -> Any:  # pragma: no cover - never started
    raise RuntimeError("contract export does not start the application")


def documents() -> dict[str, dict[str, Any]]:
    docs: dict[str, dict[str, Any]] = {
        f"schemas/{name}.schema.json": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"{BASE_ID}/{name}.schema.json",
            **model.model_json_schema(mode=mode),  # type: ignore[arg-type]
        }
        for name, (model, mode) in MODELS.items()
    }
    app: FastAPI = create_app(_no_container)
    docs["docs/api/openapi.json"] = app.openapi()
    return docs


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None, root: Path | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    base = root or Path.cwd()
    stale: list[str] = []
    for relative, document in documents().items():
        path = base / relative
        content = render(document)
        if "--check" in args:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                stale.append(relative)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
    if stale:
        sys.stderr.write(
            "stale contracts (run python -m self_healing_infrastructure_agents.contracts): "
            + ", ".join(stale)
            + "\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
