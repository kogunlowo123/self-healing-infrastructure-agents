"""Domain errors mapped to HTTP status codes and OAuth-style error bodies by the API layer."""

from __future__ import annotations


class HealingError(Exception):
    code = "invalid_request"
    status = 400

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NotFoundError(HealingError):
    code = "not_found"
    status = 404


class ConflictError(HealingError):
    """Optimistic-concurrency or duplicate-state conflict."""

    code = "conflict"
    status = 409


class InvalidStateError(HealingError):
    code = "invalid_state"
    status = 409


class UnauthorizedError(HealingError):
    code = "unauthorized"
    status = 401


class ForbiddenError(HealingError):
    code = "forbidden"
    status = 403


class PolicyViolationError(HealingError):
    """The remediation policy denied the action."""

    code = "policy_denied"
    status = 403

    def __init__(self, message: str, *, rule_ids: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.rule_ids = rule_ids


class ApprovalRequiredError(HealingError):
    code = "approval_required"
    status = 409


class InvalidPlanError(HealingError):
    """A Terraform plan document is malformed or unusable."""

    code = "invalid_plan"
    status = 422


class PlanTamperedError(HealingError):
    """The plan on disk no longer matches the reviewed and approved plan."""

    code = "plan_tampered"
    status = 409


class IntegrationError(HealingError):
    """An external system (Kubernetes API, Terraform, identity fabric) failed."""

    code = "integration_error"
    status = 502


class TargetNotFoundError(IntegrationError):
    code = "target_not_found"
    status = 404


class IntegrationUnavailableError(IntegrationError):
    code = "integration_unavailable"
    status = 503


class LiveExecutionDisabledError(HealingError):
    code = "live_execution_disabled"
    status = 409
