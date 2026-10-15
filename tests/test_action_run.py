"""The action's Scan step, run as the runner runs it: bash with the inputs in env.

Needs a POSIX bash and `python` on PATH (Linux/macOS CI). On Windows it runs only when
SKILLTOTAL_TEST_BASH names a bash (Git for Windows' bash.exe). Nothing is fetched: every source is
a folder in a temporary workspace. The snippets are inert detection fixtures.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - runs the action's own step script with bash
from pathlib import Path

import pytest

from skilltotal.scanners.shell_script import _action_commands

ROOT = Path(__file__).resolve().parent.parent
RISKY = "import pickle\nobj = pickle.loads(blob)\n"


def _bash() -> str | None:
    if os.name == "nt":
        return os.environ.get("SKILLTOTAL_TEST_BASH") or None
    return shutil.which("bash")


pytestmark = pytest.mark.skipif(
    _bash() is None or shutil.which("python") is None,
    reason="needs a POSIX bash and python on PATH",
)


def _scan_step() -> str:
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    commands = [command for command, _ in _action_commands(text)]
    return next(c for c in commands if "GATE_EXIT=0" in c)


def _run(workspace: Path, tmp_path: Path, **inputs: str) -> tuple[dict[str, str], str]:
    out = tmp_path / "github_output"
    out.write_text("", encoding="utf-8")
    env = {
        **os.environ,
        "GITHUB_OUTPUT": str(out),
        "GITHUB_ACTION_PATH": str(ROOT),
        "GITHUB_WORKSPACE": str(workspace),
        "RUNNER_TEMP": str(tmp_path),
        "INPUT_SOURCE": ".", "INPUT_VERSION": "", "INPUT_FAIL_ON": "", "INPUT_FAIL_ON_SCORE": "",
        "INPUT_FAIL_ON_UNANALYZED": "false", "INPUT_EXCLUDE": "", "INPUT_CONFIG": "",
        "INPUT_BASELINE": "", "INPUT_SARIF_FILE": "skilltotal.sarif", "INPUT_SARIF_CATEGORY": "",
    }
    env.update({f"INPUT_{k.upper()}": v for k, v in inputs.items()})
    done = subprocess.run(  # nosec B603 - bash running the action's own step
        [_bash(), "-eo", "pipefail", "-c", _scan_step()], cwd=workspace, env=env,
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600,
        check=False)
    assert done.returncode == 0, done.stderr
    outputs = dict(line.split("=", 1) for line in out.read_text(encoding="utf-8").splitlines()
                   if "=" in line)
    return outputs, done.stdout + done.stderr


def _workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "fx-high").mkdir(parents=True)
    (ws / "fx-high" / "app.py").write_text(RISKY, encoding="utf-8")
    return ws


def test_a_subfolder_source_uploads_repository_paths_and_says_why_the_gate_failed(tmp_path):
    ws = _workspace(tmp_path)
    outputs, log = _run(ws, tmp_path, source="fx-high")
    assert outputs["gate-exit"] == "2"
    assert outputs["sarif-upload"] == "true"
    assert "gate: --fail-on-default high tripped by ST-DESERIALIZE-PY (app.py:2)" in log
    assert "Findings: 1 risk finding(s)" in log
    run = json.loads((ws / "skilltotal.sarif").read_text(encoding="utf-8"))["runs"][0]
    assert run["automationDetails"] == {"id": "skilltotal/fx-high/"}
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "fx-high/app.py"


def test_the_repository_config_gate_is_used_and_named_when_fail_on_is_empty(tmp_path):
    ws = _workspace(tmp_path)
    (ws / ".skilltotal.toml").write_text('fail_on = "critical"\n', encoding="utf-8")
    outputs, log = _run(ws, tmp_path)
    assert outputs["gate-exit"] == "0"
    assert "Config    : .skilltotal.toml" in log
    # An explicit level overrides the config's; `config: none` ignores it.
    assert _run(ws, tmp_path, fail_on="high")[0]["gate-exit"] == "2"
    assert _run(ws, tmp_path, config="none")[0]["gate-exit"] == "2"


def test_fail_on_none_never_fails_even_when_the_config_sets_a_gate(tmp_path):
    ws = _workspace(tmp_path)
    (ws / ".skilltotal.toml").write_text('fail_on = "low"\n', encoding="utf-8")
    assert _run(ws, tmp_path, fail_on="none")[0]["gate-exit"] == "0"


def test_exclude_and_fail_on_score_inputs(tmp_path):
    ws = _workspace(tmp_path)
    (ws / "ok.py").write_text("x = 1\n", encoding="utf-8")  # a component with nothing read fails
    assert _run(ws, tmp_path, exclude="fx-high/*, other/*")[0]["gate-exit"] == "0"
    assert _run(ws, tmp_path, exclude="other/*\n  fx-high/*  \n")[0]["gate-exit"] == "0"
    assert _run(ws, tmp_path, fail_on="none", fail_on_score="1")[0]["gate-exit"] == "2"
