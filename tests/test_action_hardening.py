"""The composite action runs in the consumer's checkout, which may be an untrusted pull request.

Read with the engine's own decoder of `run:` steps, so each check sees the commands the way the
runner's shell receives them.
"""

from __future__ import annotations

import re
from pathlib import Path

from skilltotal.scanners.shell_script import _action_commands

ACTION = Path(__file__).resolve().parent.parent / "action.yml"


def _commands() -> list[str]:
    return [command for command, _ in _action_commands(ACTION.read_text(encoding="utf-8"))]


def test_inputs_reach_the_shell_only_through_env():
    # `${{ inputs.source }}` inside `run:` is pasted into the script before bash parses it, so
    # untrusted text such as `$(…)` would run in the consumer's runner.
    commands = _commands()
    assert commands
    for command in commands:
        assert "${{" not in command, command


def test_every_python_keeps_the_scanned_repository_off_sys_path():
    # `python -m x` and `python -c` put the working directory (the scanned repo) first on
    # sys.path, where a planted `skilltotal/`, `pip/` or `json.py` would run instead.
    calls = [m for command in _commands() for m in re.finditer(r"\bpython3?\b(\s+\S+)?", command)]
    assert calls
    for call in calls:
        assert (call.group(1) or "").strip() in ("-I", "-P"), call.group(0)


def test_an_unknown_fail_on_level_fails_instead_of_disabling_the_gate():
    text = ACTION.read_text(encoding="utf-8")
    assert "fail-on must be low, medium, high, critical or none" in text
    assert 'GATE+=(--fail-on "' in text
