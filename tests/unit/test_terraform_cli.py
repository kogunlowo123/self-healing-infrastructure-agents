"""SubprocessTerraform against a stand-in ``terraform`` executable.

The stand-in is a small Python program that answers the three commands the
runner issues, so the real argv construction, working-directory handling,
environment filtering, exit-code handling and timeouts are exercised.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from self_healing_infrastructure_agents.domain.errors import (
    HealingError,
    IntegrationError,
    IntegrationUnavailableError,
    InvalidPlanError,
)
from self_healing_infrastructure_agents.integrations.terraform_cli import SubprocessTerraform
from tests.conftest import FIXTURES

STAND_IN = r"""
import json, os, sys, time
args = sys.argv[1:]
chdir = args[0].split("=", 1)[1]
command = args[1]
log = os.environ.get("STAND_IN_LOG")
if log:
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"args": args, "secret": os.environ.get("HEAL_ALERTMANAGER_TOKEN"),
                                 "automation": os.environ.get("TF_IN_AUTOMATION")}) + "\n")
behaviour = open(os.path.join(chdir, "behaviour"), encoding="utf-8").read().strip() \
    if os.path.exists(os.path.join(chdir, "behaviour")) else "ok"
if behaviour == "sleep":
    time.sleep(30)
if command == "show":
    if behaviour == "not-json":
        print("Error: not a plan")
        sys.exit(0)
    if behaviour == "fail":
        print("Error: plan file corrupt", file=sys.stderr)
        sys.exit(1)
    sys.stdout.write(open(os.path.join(chdir, args[-1] + ".json"), encoding="utf-8").read())
    sys.exit(0)
if command == "apply":
    sys.exit(1 if behaviour == "fail" else 0)
if command == "plan":
    if "-detailed-exitcode" in args:
        sys.exit(2 if behaviour == "drift" else 0)
    out = [a for a in args if a.startswith("-out=")][0].split("=", 1)[1]
    open(os.path.join(chdir, out), "w").write("binary plan")
    sys.exit(0)
sys.exit(3)
"""


@pytest.fixture
def root(tmp_path: Path) -> Path:
    stack = tmp_path / "stacks" / "rds" / "orders"
    stack.mkdir(parents=True)
    (stack / "resize.tfplan").write_text("binary plan", encoding="utf-8")
    (stack / "resize.tfplan.json").write_text(
        (FIXTURES / "terraform" / "aws-rds-storage-resize.plan.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (tmp_path / "stand_in.py").write_text(STAND_IN, encoding="utf-8")
    return tmp_path


def runner(root: Path, **kw: object) -> SubprocessTerraform:
    env = {
        "PATH": "/usr/bin",
        "SYSTEMROOT": "C:\\Windows",
        "HEAL_ALERTMANAGER_TOKEN": "must-not-leak",
        "STAND_IN_LOG": str(root / "calls.jsonl"),
    }
    return SubprocessTerraform(
        root / "stacks",
        command=(sys.executable, str(root / "stand_in.py")),
        env=env,
        env_allow=("PATH", "SYSTEMROOT", "STAND_IN_LOG"),
        **kw,  # type: ignore[arg-type]
    )


def behaviour(root: Path, value: str) -> None:
    (root / "stacks" / "rds" / "orders" / "behaviour").write_text(value, encoding="utf-8")


async def test_show_plan_returns_document(root: Path) -> None:
    document = await runner(root).show_plan("rds/orders", "resize.tfplan")
    assert document["format_version"] == "1.2"
    call = json.loads((root / "calls.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert call["args"][1:] == ["show", "-json", "resize.tfplan"]
    assert call["secret"] is None  # service secrets are not inherited
    assert call["automation"] == "1"


async def test_apply_plan_and_converged(root: Path) -> None:
    terraform = runner(root)
    applied = await terraform.apply("rds/orders", "resize.tfplan")
    assert applied.exit_code == 0
    assert applied.args == ("apply", "-input=false", "-no-color", "resize.tfplan")
    planned = await terraform.plan("rds/orders", "rollback-1.tfplan")
    assert planned.exit_code == 0
    assert (root / "stacks" / "rds" / "orders" / "rollback-1.tfplan").is_file()
    assert (await terraform.check_converged("rds/orders")).exit_code == 0
    behaviour(root, "drift")
    assert (await terraform.check_converged("rds/orders")).exit_code == 2


async def test_failures(root: Path) -> None:
    behaviour(root, "fail")
    with pytest.raises(IntegrationError, match="terraform show failed"):
        await runner(root).show_plan("rds/orders", "resize.tfplan")
    assert (await runner(root).apply("rds/orders", "resize.tfplan")).exit_code == 1
    behaviour(root, "not-json")
    with pytest.raises(InvalidPlanError):
        await runner(root).show_plan("rds/orders", "resize.tfplan")


async def test_timeout_kills_process(root: Path) -> None:
    behaviour(root, "sleep")
    with pytest.raises(IntegrationUnavailableError, match="exceeded"):
        await runner(root, timeout_s=0.5).apply("rds/orders", "resize.tfplan")


async def test_missing_binary(root: Path) -> None:
    terraform = SubprocessTerraform(root / "stacks", command=(str(root / "no-such-terraform"),))
    with pytest.raises(IntegrationUnavailableError, match="cannot start"):
        await terraform.apply("rds/orders", "resize.tfplan")


@pytest.mark.parametrize(
    ("stack", "plan_file"),
    [
        ("../outside", "resize.tfplan"),
        ("rds/../../etc", "resize.tfplan"),
        ("/abs", "resize.tfplan"),
        ("rds/orders", "../resize.tfplan"),
        ("rds/orders", "missing.tfplan"),
        ("rds/missing", "resize.tfplan"),
        ("rds/orders", "a..b"),
    ],
)
async def test_paths_cannot_escape_root(root: Path, stack: str, plan_file: str) -> None:
    with pytest.raises(HealingError):
        await runner(root).apply(stack, plan_file)


async def test_symlink_escape_rejected(root: Path) -> None:
    outside = root / "outside"
    outside.mkdir()
    try:
        (root / "stacks" / "escape").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not permitted on this platform")
    with pytest.raises(HealingError, match="not a directory under"):
        await runner(root).check_converged("escape")


async def test_invalid_out_file(root: Path) -> None:
    with pytest.raises(HealingError, match="invalid plan file"):
        await runner(root).plan("rds/orders", "../x")


def test_default_environment_allow_list(root: Path) -> None:
    terraform = SubprocessTerraform(root / "stacks", env={"PATH": "/bin", "SECRET": "x"})
    assert terraform._env == {
        "PATH": "/bin",
        "TF_IN_AUTOMATION": "1",
        "TF_INPUT": "0",
        "NO_COLOR": "1",
    }
