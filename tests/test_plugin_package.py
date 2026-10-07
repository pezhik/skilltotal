"""The Claude Code plugin as Claude Code loads it: manifests, the hook wiring and the shell wrapper.

`test_agent_hook.py` covers the parser and the answer. These tests cover the glue around them,
which no unit test of `agent_hook` would catch breaking: a renamed script, a manifest field, a hook
timeout shorter than the CLI's own budget, or a wrapper that drops a command before the parser
sees it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import skilltotal
from skilltotal.cli import HOOK_BUDGET_S, build_parser
from tests.test_agent_hook import (
    DIFFERENTIAL_COMMANDS,
    GITHUB_COMMANDS,
    INSTALL_COMMANDS,
    UNVERIFIABLE_COMMANDS,
)

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
MARKETPLACE = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
HOOKS = json.loads((ROOT / "hooks" / "hooks.json").read_text(encoding="utf-8"))
WRAPPER = ROOT / "hooks" / "pretooluse.sh"


def _bash_hooks() -> list[dict]:
    return [
        hook
        for entry in HOOKS["hooks"]["PreToolUse"]
        if entry["matcher"] == "Bash"
        for hook in entry["hooks"]
    ]


# --- Manifests --------------------------------------------------------------------------------


def test_the_marketplace_lists_this_repository_as_the_plugin():
    (entry,) = MARKETPLACE["plugins"]
    assert entry["name"] == PLUGIN["name"] == MARKETPLACE["name"] == "skilltotal"
    assert entry["source"] == "./"


def test_the_plugin_version_is_the_engine_version():
    """Claude Code updates an installed plugin when its `version` changes. Tying it to the engine
    release ships the hook together with the CLI that answers it, not on every commit to main."""
    assert PLUGIN["version"] == skilltotal.__version__


def test_the_plugin_carries_what_the_directory_listing_shows():
    for field in ("description", "author", "homepage", "repository", "license"):
        assert PLUGIN[field], field


def test_the_bash_hook_runs_the_wrapper_that_ships_in_the_repository():
    (hook,) = _bash_hooks()
    assert hook["type"] == "command"
    assert '"${CLAUDE_PLUGIN_ROOT}/hooks/pretooluse.sh"' in hook["command"]
    assert WRAPPER.is_file()


def test_the_hook_timeout_outlasts_the_cli_budget():
    """Claude Code kills a hook at its timeout. The CLI must answer first, inside its own budget,
    or a slow scan ends as a killed hook instead of the 'not checked in time' note."""
    (hook,) = _bash_hooks()
    assert hook["timeout"] >= HOOK_BUDGET_S + 30


def test_every_cli_command_the_plugin_calls_exists():
    parser = build_parser()
    parser.parse_args(["hook", "claude-code"])
    server = PLUGIN["mcpServers"]["skilltotal"]
    assert server["command"] == "skilltotal"
    parser.parse_args(server["args"])
    scan_command = (ROOT / "commands" / "scan.md").read_text(encoding="utf-8")
    assert "skilltotal scan $ARGUMENTS --json" in scan_command
    parser.parse_args(["scan", "x", "--json"])


# --- The shell wrapper ------------------------------------------------------------------------

SH = shutil.which("sh")
needs_sh = pytest.mark.skipif(SH is None, reason="no POSIX sh on this machine")

STUB = """#!/bin/sh
printf '%s' "$*" > "$ST_STUB_ARGS"
cat > "$ST_STUB_STDIN"
printf '%s' "$ST_STUB_OUT"
exit "${ST_STUB_RC:-0}"
"""


def _run_wrapper(
    tmp_path: Path, command: str, *, with_cli: bool = True, cli_rc: int = 0,
    cli_out: str = '{"answer": "from the cli"}',
):
    """Run hooks/pretooluse.sh the way Claude Code does, with a stand-in `skilltotal` on PATH."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    if with_cli:
        stub = bin_dir / "skilltotal"
        stub.write_text(STUB, encoding="utf-8", newline="\n")
        stub.chmod(0o755)
    # Only the stub and the shell's own tools, so a real `skilltotal` on this machine can't answer.
    path = os.pathsep.join([str(bin_dir), str(Path(SH).parent)])
    if not with_cli and shutil.which("skilltotal", path=path):
        pytest.skip("a skilltotal next to sh on this machine")
    env = {
        "PATH": path,
        "ST_STUB_ARGS": str(tmp_path / "args"),
        "ST_STUB_STDIN": str(tmp_path / "stdin"),
        "ST_STUB_OUT": cli_out,
        "ST_STUB_RC": str(cli_rc),
    }
    if "SYSTEMROOT" in os.environ:  # Windows processes need it to start
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    event = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    done = subprocess.run(  # noqa: S603 - fixed argv: the shell and our own script
        [SH, str(WRAPPER)],
        input=event.encode(),
        env=env,
        capture_output=True,
        timeout=60,
    )
    return done, event


ALL_INSTALLS = (
    [command for command, _ in INSTALL_COMMANDS]
    + DIFFERENTIAL_COMMANDS
    + [command for command, _ in GITHUB_COMMANDS]
    + UNVERIFIABLE_COMMANDS
)


@needs_sh
@pytest.mark.parametrize("command", ALL_INSTALLS)
def test_the_wrapper_hands_every_install_to_the_cli_unchanged(tmp_path, command):
    """The parser can only judge what it is given: no install may stop at the shell."""
    done, event = _run_wrapper(tmp_path, command)
    assert done.returncode == 0
    assert (tmp_path / "args").read_text(encoding="utf-8") == "hook claude-code"
    assert (tmp_path / "stdin").read_bytes().decode() == event
    assert done.stdout.decode().strip() == '{"answer": "from the cli"}'


@needs_sh
def test_a_silent_cli_answer_stays_silent(tmp_path):
    done, _ = _run_wrapper(tmp_path, "ls -la", cli_out="")
    assert done.returncode == 0
    assert done.stdout == b""


def _warning(done) -> dict:
    assert done.returncode == 0
    answer = json.loads(done.stdout.decode())
    # A warning, never a decision: the install goes ahead as if the plugin were not there.
    assert "permissionDecision" not in answer["hookSpecificOutput"]
    assert "did not check this install" in answer["hookSpecificOutput"]["additionalContext"]
    return answer


@needs_sh
@pytest.mark.parametrize("command", ["npm install lodash", "NPX evil", "p\"i\"p install x"])
def test_without_the_cli_an_install_warns_the_person_and_proceeds(tmp_path, command):
    """A missing CLI must not look like protection that found nothing."""
    answer = _warning(_run_wrapper(tmp_path, command, with_cli=False)[0])
    assert "not on PATH" in answer["systemMessage"]
    assert "pip install -U skilltotal" in answer["systemMessage"]


@needs_sh
def test_a_broken_cli_warns_the_person_and_proceeds(tmp_path):
    """Seen 2026-10-07: a stale editable install whose module was gone; and a CLI older than
    `hook` exits 2 on the unknown command. Either way nothing was checked."""
    answer = _warning(_run_wrapper(tmp_path, "npm install lodash", cli_rc=3)[0])
    assert "failed to run" in answer["systemMessage"]


@needs_sh
def test_without_the_cli_other_commands_stay_quiet(tmp_path):
    """The warning is for installs; it must not fire on every `ls` the agent runs."""
    done, _ = _run_wrapper(tmp_path, "ls -la", with_cli=False)
    assert done.returncode == 0
    assert done.stdout == b""
