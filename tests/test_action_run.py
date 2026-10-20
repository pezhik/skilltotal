"""The action's Scan step, run as the runner runs it: bash with the inputs in env.

Needs a POSIX bash and Python 3.11+ as `python` on PATH (Linux/macOS CI). On Windows it runs only
when SKILLTOTAL_TEST_BASH names a bash (Git for Windows' bash.exe). Nothing is fetched: every source
is a folder in a temporary workspace. The snippets are inert detection fixtures.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess  # nosec B404 - runs the action's own step script with bash
from pathlib import Path

import pytest

from skilltotal.scanners.shell_script import _RUN_KEY, _action_commands, _indent, _yaml_value

ROOT = Path(__file__).resolve().parent.parent
RISKY = "import pickle\nobj = pickle.loads(blob)\n"


def _bash() -> str | None:
    if os.name == "nt":
        return os.environ.get("SKILLTOTAL_TEST_BASH") or None
    return shutil.which("bash")


def _python_has_safe_path() -> bool:
    """The step runs `python -P`, which needs 3.11+; the action itself sets up Python 3.12."""
    python = shutil.which("python")
    if python is None:
        return False
    done = subprocess.run(  # nosec B603 - asks the PATH python for its version
        [python, "-c", "import sys; print(sys.version_info >= (3, 11))"],
        capture_output=True, text=True, timeout=60, check=False)
    return done.stdout.strip() == "True"


pytestmark = pytest.mark.skipif(
    _bash() is None or not _python_has_safe_path(),
    reason="needs a POSIX bash and Python 3.11+ (as the action sets up) on PATH",
)


def _scan_step() -> str:
    # The `run:` value as the runner gets it, comments and all: `_action_commands` drops shell
    # comments, which would also cut the `#` lines out of the step's Python heredocs.
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    for match in _RUN_KEY.finditer(text):
        key_line = text.rfind("\n", 0, match.start()) + 1
        command = "".join(_yaml_value(text, match.end(), _indent(text, key_line))[0])
        if "GATE_EXIT=0" in command:
            return command
    raise AssertionError("no Scan step in action.yml")


def _run(workspace: Path, tmp_path: Path, github: dict[str, str] | None = None,
         stdout_only: bool = False, **inputs: str) -> tuple[dict[str, str], str]:
    """The step's outputs and its log: stdout, then stderr (the order within each is kept, not
    across them), or only stdout, where the step's own commands go."""
    out = tmp_path / "github_output"
    out.write_text("", encoding="utf-8")
    env = {
        **os.environ,
        "GITHUB_OUTPUT": str(out),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "step_summary.md"),
        "GITHUB_ACTION_PATH": str(ROOT),
        "GITHUB_WORKSPACE": str(workspace),
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_EVENT_NAME": "push", "GITHUB_BASE_REF": "",
        "INPUT_SOURCE": ".", "INPUT_VERSION": "", "INPUT_FAIL_ON": "", "INPUT_FAIL_ON_SCORE": "",
        "INPUT_FAIL_ON_UNANALYZED": "false", "INPUT_EXCLUDE": "", "INPUT_CONFIG": "",
        "INPUT_BASELINE": "", "INPUT_SARIF_FILE": "skilltotal.sarif", "INPUT_SARIF_CATEGORY": "",
    }
    env.update({f"INPUT_{k.upper()}": v for k, v in inputs.items()})
    env.update(github or {})
    # From a file, as the runner runs it: on Windows a long `-c` argument loses characters.
    script = tmp_path / "scan_step.sh"
    script.write_bytes(_scan_step().encode("utf-8"))
    done = subprocess.run(  # nosec B603 - bash running the action's own step
        [_bash(), "-eo", "pipefail", str(script)], cwd=workspace, env=env,
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600,
        check=False)
    assert done.returncode == 0, done.stderr
    outputs = dict(line.split("=", 1) for line in out.read_text(encoding="utf-8").splitlines()
                   if "=" in line)
    return outputs, done.stdout + ("" if stdout_only else done.stderr)


def _after_resume(log: str) -> str:
    """What the step printed once workflow commands were back on (only that can annotate)."""
    token = log.split("::stop-commands::", 1)[1].split("\n", 1)[0]
    return log.split(f"::{token}::", 1)[1]


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
    # The gate the action sets when `fail-on` is empty is named as the action's default, in the
    # log and, once workflow commands are back on, as an error annotation.
    assert "gate: fail-on high (action default) tripped by ST-DESERIALIZE-PY (app.py:2)" in log
    assert "--fail-on-default" not in log
    assert ("::error::SkillTotal gate: fail-on high (action default) tripped by ST-DESERIALIZE-PY "
            "(app.py:2)") in _after_resume(log)
    assert "Findings: 1 risk finding(s)" in log
    # One report and one gate line: the SARIF run is quiet and never gated.
    assert log.count("SkillTotal Security Report") == 1
    assert sum(line.startswith("gate: ") for line in log.splitlines()) == 1
    assert outputs["sarif-written"] == "true"
    summary = (tmp_path / "step_summary.md").read_text(encoding="utf-8")
    assert "**Gate:** **failed**" in summary
    assert "| HIGH | ` ST-DESERIALIZE-PY ` | ` app.py:2 ` |" in summary
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


def test_a_sarif_file_in_a_folder_that_does_not_exist_is_written(tmp_path):
    ws = _workspace(tmp_path)
    outputs, log = _run(ws, tmp_path, source="fx-high", sarif_file="out/reports/st.sarif")
    assert outputs["sarif-written"] == "true"
    assert json.loads((ws / "out" / "reports" / "st.sarif").read_text(encoding="utf-8"))["runs"]
    assert "did not write the SARIF report" not in log


def test_unread_code_is_a_warning_annotation_not_a_failed_gate(tmp_path):
    # Bytecode with no source beside it: the gate stays opt-in (exit 0), but the file is named
    # in the log and as a warning annotation, never passed over in silence.
    ws = _workspace(tmp_path)
    (ws / "fx-pyc").mkdir()
    (ws / "fx-pyc" / "app.py").write_text("x = 1\n", encoding="utf-8")
    (ws / "fx-pyc" / "helper.pyc").write_bytes(importlib.util.MAGIC_NUMBER + b"\x00" * 60)
    outputs, log = _run(ws, tmp_path, source="fx-pyc")
    assert outputs["gate-exit"] == "0"
    assert "Not everything was analyzed: Compiled code shipped without source." in log
    assert ("::warning::SkillTotal: Not everything was analyzed: Compiled code shipped without "
            "source.") in _after_resume(log)
    assert "::error::SkillTotal gate" not in log


def test_a_sarif_report_that_cannot_be_written_is_a_warning_with_the_reason(tmp_path):
    ws = _workspace(tmp_path)
    (ws / "taken").write_text("a file, not a folder\n", encoding="utf-8")
    outputs, log = _run(ws, tmp_path, source="fx-high", sarif_file="taken/st.sarif")
    assert outputs["sarif-written"] == "false"
    assert outputs["gate-exit"] == "2"  # the JSON run still decides the gate
    warning = next(line for line in _after_resume(log).splitlines()
                   if line.startswith("::warning::SkillTotal did not write the SARIF report"))
    assert "taken/st.sarif (exit 1): cannot write the report to taken/st.sarif" in warning


def test_a_scan_that_cannot_run_is_not_reported_as_a_tripped_gate(tmp_path):
    ws = _workspace(tmp_path)
    outputs, log = _run(ws, tmp_path, source="fx-high", config="missing.toml")
    assert outputs["gate-exit"] == "1"
    assert "missing.toml" in outputs["scan-error"]
    assert outputs["sarif-written"] == "false"
    assert "::error::SkillTotal gate" not in log
    assert "did not write the SARIF report" not in log  # nothing to describe; the error says why
    summary = (tmp_path / "step_summary.md").read_text(encoding="utf-8")
    assert "**SkillTotal could not run the scan** (exit 1): " in summary


def _enforce(tmp_path: Path, **env: str) -> subprocess.CompletedProcess:
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    step = next(c for c, _ in _action_commands(text) if "SCAN_ERROR:-" in c)
    script = tmp_path / "enforce.sh"
    script.write_bytes(step.encode("utf-8"))
    return subprocess.run(  # nosec B603 - bash running the action's own step
        [_bash(), "-eo", "pipefail", str(script)], env={**os.environ, **env},
        capture_output=True, text=True, encoding="utf-8", timeout=60, check=False)


def test_the_enforce_step_names_an_error_apart_from_a_tripped_gate(tmp_path):
    error = _enforce(tmp_path, EXIT="1", SCAN_ERROR="cannot read config x.toml")
    assert error.returncode == 1
    assert error.stdout.strip() == (
        "::error::SkillTotal could not run the scan (exit 1): cannot read config x.toml")
    gate = _enforce(tmp_path, EXIT="2", SCAN_ERROR="")
    assert gate.returncode == 2
    assert gate.stdout.startswith("::error::SkillTotal gate failed (exit 2).")
    assert _enforce(tmp_path, EXIT="0", SCAN_ERROR="").returncode == 0


def _before_stop(log: str) -> str:
    return log.split("::stop-commands::", 1)[0]


def test_an_input_with_a_newline_cannot_forge_a_workflow_command(tmp_path):
    ws = _workspace(tmp_path)
    forged = "fx-high\n::error title=FORGED::gate passed"
    for inputs in ({"source": forged}, {"source": "npm:" + forged},
                   {"fail_on": "high\n::error title=FORGED::x"},
                   {"fail_on_unanalyzed": "no\n::error title=FORGED::x"},
                   {"source": "fx-high", "sarif_file": "taken\n::error title=FORGED::x/st.sarif"}):
        _, log = _run(ws, tmp_path, stdout_only=True, **inputs)
        # Commands are off from the first line the step prints until its own annotations; what
        # the scan prints to stderr comes in between, while they are off.
        assert _before_stop(log).strip() == "", inputs
        assert not any(line.startswith("::error title=FORGED")
                       for line in _after_resume(log).splitlines()), inputs
    # The step's own error still reaches the log as a command, the input escaped on its line.
    outputs, log = _run(ws, tmp_path, fail_on="high\n::error title=FORGED::x")
    assert outputs["gate-exit"] == "1"
    assert ("::error::fail-on must be low, medium, high, critical or none (or empty for the "
            "config's gate, else high) (got 'high%0A::error title=FORGED::x')"
            ) in _after_resume(log)


def test_the_summary_and_the_comment_name_the_applied_config(tmp_path):
    ws = _workspace(tmp_path)
    (ws / ".skilltotal.toml").write_text(
        'fail_on = "critical"\nexclude = ["docs/*"]\nbaseline = "bl.json"\n', encoding="utf-8")
    (ws / "bl.json").write_text('{"version": 1, "suppressed": []}\n', encoding="utf-8")
    _run(ws, tmp_path)
    line = ("**Config:** ` .skilltotal.toml ` (1 exclude(s), 0 ignored rule(s), 0 policy "
            "override(s), fail_on critical, baseline ` bl.json `)")
    assert line in (tmp_path / "step_summary.md").read_text(encoding="utf-8")
    assert line in (tmp_path / "skilltotal-comment.md").read_text(encoding="utf-8")
    # No config applied, no line.
    _run(ws, tmp_path, config="none")
    assert "**Config:**" not in (tmp_path / "skilltotal-comment.md").read_text(encoding="utf-8")


def test_an_issue_reference_in_escaped_text_is_not_a_link(tmp_path):
    ws = _workspace(tmp_path)
    _run(ws, tmp_path, source="fx-high", config="missing#12 GH-7.toml")
    summary = (tmp_path / "step_summary.md").read_text(encoding="utf-8")
    assert "missing\\#​12 GH\\-​7\\.toml" in summary


def _git(repo: Path, *argv: str) -> None:
    subprocess.run(["git", "-C", str(repo), *argv], check=True, capture_output=True,  # nosec B603
                   timeout=60)


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_a_pull_request_that_changes_the_config_gets_a_warning(tmp_path):
    ws = _workspace(tmp_path)
    (ws / ".skilltotal.toml").write_text('fail_on = "high"\n', encoding="utf-8")
    _git(ws, "init", "-q")
    _git(ws, "add", "-A")
    _git(ws, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "base")
    _git(ws, "update-ref", "refs/remotes/origin/main", "HEAD")
    pr = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_BASE_REF": "main"}
    warning = "::warning::This pull request changes the scanner config .skilltotal.toml"
    assert warning not in _run(ws, tmp_path, pr)[1]  # the same config as the base branch
    (ws / ".skilltotal.toml").write_text('fail_on = "critical"\n', encoding="utf-8")
    assert warning in _after_resume(_run(ws, tmp_path, pr)[1])
    assert warning not in _run(ws, tmp_path)[1]  # not a pull request
    # A base branch that was not fetched: nothing to compare, nothing said.
    log = _run(ws, tmp_path, {**pr, "GITHUB_BASE_REF": "release"})[1]
    assert "changes the scanner config" not in log


def test_a_sarif_folder_that_is_a_link_is_refused(tmp_path):
    ws = _workspace(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "st.sarif").write_text("keep me", encoding="utf-8")
    try:
        (ws / "reports").symlink_to(outside, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            raise
        subprocess.run(["cmd", "/c", "mklink", "/J", str(ws / "reports"), str(outside)],  # noqa: S603,S607 # nosec
                       check=True, capture_output=True, timeout=60)
    outputs, _ = _run(ws, tmp_path, source="fx-high", sarif_file="reports/sub/st.sarif")
    assert outputs["sarif-written"] == "false"
    assert not (outside / "sub").exists()  # nothing created through the link
    outputs, log = _run(ws, tmp_path, source="fx-high", sarif_file="reports/st.sarif")
    assert outputs["sarif-written"] == "false"
    assert (outside / "st.sarif").read_text(encoding="utf-8") == "keep me"
    assert ("reports is a symbolic link or junction; refusing to write the SARIF report"
            in _after_resume(log))
