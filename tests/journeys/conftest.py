"""Customer journeys: the CLI driven as a DevOps or security team drives it, from a shell.

Unit tests call functions; these run the command a customer runs and read only what the customer
sees (exit code, console, files written). In CI the `journeys` job installs the built wheel with
pipx and points SKILLTOTAL_JOURNEY_CLI at it, so the packaging, the console script and the README's
commands are what is tested. Without it the journeys run this checkout as `python -m skilltotal`.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess  # nosec B404 - runs the CLI under test with fixed arguments
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
# Variables that change what the CLI or the hook does; a journey sets the ones it needs.
_CONTROLLED = ("CI", "GITHUB_ACTIONS", "TF_BUILD", "JENKINS_URL", "TEAMCITY_VERSION",
               "CODEBUILD_BUILD_ID", "BUILDKITE", "GITLAB_CI")


@dataclass
class Run:
    code: int
    out: str
    err: str


def cli_command() -> list[str]:
    installed = os.environ.get("SKILLTOTAL_JOURNEY_CLI")
    if installed:
        return shlex.split(installed, posix=os.name != "nt")
    return [sys.executable, "-m", "skilltotal"]


def clean_env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items()
           if k not in _CONTROLLED and not k.startswith("SKILLTOTAL_")}
    if not os.environ.get("SKILLTOTAL_JOURNEY_CLI"):
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(ROOT), env.get("PYTHONPATH")]))
    env["PYTHONIOENCODING"] = "utf-8"
    env.update(extra)
    return env


@pytest.fixture
def skilltotal():
    """``skilltotal(*args, cwd=None, stdin=None, **env)`` runs the CLI and returns a Run."""
    def run(*args: str, cwd: Path | None = None, stdin: str | None = None, **env: str) -> Run:
        done = subprocess.run(  # nosec B603 - the CLI under test, fixed arguments
            [*cli_command(), *args], cwd=cwd, input=stdin, capture_output=True, text=True,
            encoding="utf-8", errors="replace", env=clean_env(**env), timeout=600, check=False)
        return Run(done.returncode, done.stdout, done.stderr)
    return run


@pytest.fixture
def fixture_copy(tmp_path):
    """A fixture component copied out of the repository, so it is scanned as a customer's own."""
    def copy(name: str) -> Path:
        target = tmp_path / name
        shutil.copytree(FIXTURES / name, target)
        return target
    return copy


def git(repo: Path, *argv: str) -> None:
    subprocess.run(["git", "-C", str(repo), *argv], check=True, capture_output=True)  # nosec


needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
needs_sh = pytest.mark.skipif(shutil.which("sh") is None, reason="needs sh")
