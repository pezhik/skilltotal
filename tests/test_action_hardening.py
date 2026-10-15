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


def test_the_pull_request_comment_puts_malicious_indicators_first():
    # A dropper can score 20/100 (low): the icon must not go green over malicious indicators.
    text = ACTION.read_text(encoding="utf-8")
    assert "verdict.has_malicious_indicators === true ? '🔴'" in text


def test_sarif_from_a_source_outside_the_repository_is_not_uploaded():
    # Alerts for an npm:/pypi: package or a git URL would point at files the repository lacks.
    text = ACTION.read_text(encoding="utf-8")
    assert "npm:*|pypi:*|http://*|https://*|git@*|ssh://*|git://*|git+*) SARIF_UPLOAD=false" in text
    upload = text.split("- name: Upload SARIF to Code Scanning", 1)[1].split("- name:", 1)[0]
    assert "steps.scan.outputs.sarif-upload == 'true'" in upload


def test_the_pull_request_comment_counts_risk_apart_from_capabilities_and_says_the_gate():
    text = ACTION.read_text(encoding="utf-8")
    comment = text.split("- name: Comment on PR", 1)[1].split("- name:", 1)[0]
    assert "GATE_EXIT: ${{ steps.scan.outputs.gate-exit }}" in comment
    assert "f.threat_class !== 'capability'" in comment
    assert "**Gate:** " in comment
    assert "capability finding(s), not scored" in comment


def test_new_inputs_reach_the_cli_through_env():
    text = ACTION.read_text(encoding="utf-8")
    for name in ("fail-on-score", "exclude", "config", "sarif-category"):
        env = "INPUT_" + name.upper().replace("-", "_")
        assert f"{env}: ${{{{ inputs.{name} }}}}" in text, name
    fail_on = text.split("  fail-on:\n", 1)[1].split("\n  fail-on-score:", 1)[0]
    assert 'default: ""' in fail_on
    assert '"") GATE+=(--fail-on-default high) ;;' in text
