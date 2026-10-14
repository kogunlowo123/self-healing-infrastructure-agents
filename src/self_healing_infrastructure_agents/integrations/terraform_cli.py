"""Terraform CLI runner.

Only stacks under a configured root directory can be touched, and only
through three fixed commands:

* ``terraform show -json <plan>``      read a saved plan for analysis;
* ``terraform apply <plan>``           apply exactly that saved plan;
* ``terraform plan -detailed-exitcode`` post-check: exit 0 means the live
  infrastructure matches the configuration.

Arguments are passed as an argv vector (never a shell string); stack names
and plan file names are validated and resolved so neither can escape the
root through ``..`` or symlinks. The child environment is an explicit
allow list so service secrets are not inherited by Terraform providers.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from self_healing_infrastructure_agents.domain.errors import (
    HealingError,
    IntegrationError,
    IntegrationUnavailableError,
    InvalidPlanError,
)
from self_healing_infrastructure_agents.domain.models import PLAN_FILE_PATTERN, STACK_PATTERN
from self_healing_infrastructure_agents.domain.ports import CommandResult

MAX_PLAN_BYTES = 64 * 1024 * 1024
TAIL = 4000

# Variables Terraform and its cloud providers legitimately need (workload identity
# web-identity files, regions, proxies). Everything else is withheld.
DEFAULT_ENV_ALLOW = (
    "PATH",
    "HOME",
    "TMPDIR",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "TF_PLUGIN_CACHE_DIR",
    "TF_CLI_CONFIG_FILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_ROLE_ARN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_STS_REGIONAL_ENDPOINTS",
    "AZURE_CLIENT_ID",
    "AZURE_TENANT_ID",
    "AZURE_FEDERATED_TOKEN_FILE",
    "AZURE_AUTHORITY_HOST",
    "ARM_USE_OIDC",
    "ARM_SUBSCRIPTION_ID",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_PROJECT",
    "SYSTEMROOT",
)


def _tail(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")[-TAIL:]


class SubprocessTerraform:
    def __init__(
        self,
        root: Path,
        *,
        command: Sequence[str] = ("terraform",),
        timeout_s: float = 1800.0,
        env: Mapping[str, str] | None = None,
        env_allow: Sequence[str] = DEFAULT_ENV_ALLOW,
    ) -> None:
        self._root = root.resolve()
        self._command = tuple(command)
        self._timeout = timeout_s
        source = os.environ if env is None else env
        self._env = {k: source[k] for k in env_allow if k in source}
        self._env.update({"TF_IN_AUTOMATION": "1", "TF_INPUT": "0", "NO_COLOR": "1"})

    def stack_dir(self, stack: str) -> Path:
        if not STACK_PATTERN.fullmatch(stack):
            raise HealingError(f"invalid stack name {stack!r}")
        directory = (self._root / stack).resolve()
        if not directory.is_relative_to(self._root) or not directory.is_dir():
            raise HealingError(f"stack {stack!r} is not a directory under the Terraform root")
        return directory

    def plan_path(self, stack: str, plan_file: str) -> Path:
        directory = self.stack_dir(stack)
        if not PLAN_FILE_PATTERN.fullmatch(plan_file) or ".." in plan_file:
            raise HealingError(f"invalid plan file name {plan_file!r}")
        path = (directory / plan_file).resolve()
        if not path.is_relative_to(directory) or not path.is_file():
            raise HealingError(f"plan file {plan_file!r} not found in stack {stack!r}")
        return path

    async def _run(self, directory: Path, *args: str) -> tuple[CommandResult, bytes]:
        argv = (*self._command, f"-chdir={directory}", *args)
        started = time.monotonic()
        try:
            # argv vector, no shell; arguments are validated above.
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._env,
            )
        except OSError as exc:
            raise IntegrationUnavailableError(f"cannot start terraform: {exc}") from exc
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), self._timeout)
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise IntegrationUnavailableError(
                f"terraform {args[0]} exceeded {self._timeout:.0f}s"
            ) from exc
        result = CommandResult(
            args=tuple(args),
            exit_code=process.returncode if process.returncode is not None else -1,
            stdout_tail=_tail(stdout),
            stderr_tail=_tail(stderr),
            duration_s=round(time.monotonic() - started, 3),
        )
        return result, stdout

    async def show_plan(self, stack: str, plan_file: str) -> dict[str, Any]:
        path = self.plan_path(stack, plan_file)
        result, stdout = await self._run(path.parent, "show", "-json", path.name)
        if result.exit_code != 0:
            raise IntegrationError(f"terraform show failed: {result.stderr_tail[-500:]}")
        if len(stdout) > MAX_PLAN_BYTES:
            raise InvalidPlanError("plan JSON exceeds the size limit")
        try:
            document: dict[str, Any] = json.loads(stdout)
        except ValueError as exc:
            raise InvalidPlanError("terraform show did not return JSON") from exc
        return document

    async def plan(self, stack: str, out_file: str) -> CommandResult:
        directory = self.stack_dir(stack)
        if not PLAN_FILE_PATTERN.fullmatch(out_file) or ".." in out_file:
            raise HealingError(f"invalid plan file name {out_file!r}")
        result, _ = await self._run(
            directory, "plan", "-input=false", "-no-color", "-lock-timeout=120s", f"-out={out_file}"
        )
        return result

    async def apply(self, stack: str, plan_file: str) -> CommandResult:
        path = self.plan_path(stack, plan_file)
        result, _ = await self._run(path.parent, "apply", "-input=false", "-no-color", path.name)
        return result

    async def check_converged(self, stack: str) -> CommandResult:
        directory = self.stack_dir(stack)
        result, _ = await self._run(
            directory,
            "plan",
            "-detailed-exitcode",
            "-input=false",
            "-no-color",
            "-lock-timeout=120s",
        )
        return result
