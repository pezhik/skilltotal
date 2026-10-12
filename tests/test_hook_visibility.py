"""What the hook checks, and what it does not, is said in the person's console.

Every command that installs something gets one line (`systemMessage`): the packages checked with
their risk, the decision, and what installs with no package name to check (a lockfile or
requirements file, a local path, a downloaded script piped to a shell). Those were silent before:
a lockfile install looked exactly like a checked one. URLs below are reserved `.invalid` names;
nothing is fetched or run.
"""

from __future__ import annotations

import io
import json
import sys

import pytest

from skilltotal import cli
from skilltotal.agent_hook import (
    MAX_TARGETS,
    hook_response,
    install_targets,
    parse_installs,
)

NAMES_ONLY = "and SkillTotal checks only the packages a command names."
URL = "https://get.example.invalid/install.sh"


def _bash(command):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}}


def _powershell(command):
    return {"hook_event_name": "PreToolUse", "tool_name": "PowerShell",
            "tool_input": {"command": command}}


def _report(level="low", score=0, malicious=False, version=None, findings=None):
    report = {"risk_level": level, "risk_score": score, "findings": findings or [],
              "verdict": {"has_malicious_indicators": malicious, "headline": "Headline"}}
    if version:
        report["component"] = {"version": version}
    return report


def _no_scan(command, shell="bash", **options):
    calls = []
    event = _bash(command) if shell == "bash" else _powershell(command)
    out = hook_response(event, scan=lambda s, t: calls.append(s) or _report(), **options)
    assert calls == []
    return out


# --- A.1 Checked and clean: the packages and their risk -----------------------------------------


def test_a_checked_package_is_named_in_the_console_with_its_risk():
    out = hook_response(_bash("npm install express"), scan=lambda s, t: _report(version="5.1.0"))
    assert out["systemMessage"] == ("SkillTotal checked npm:express@5.1.0: risk 0/100 (low). Its "
                                    "dependencies were not checked.")
    spec = out["hookSpecificOutput"]
    assert "permissionDecision" not in spec  # never "allow": the normal permission flow decides
    assert spec["additionalContext"] == (
        "SkillTotal checked npm:express@5.1.0: risk 0/100 (low), no malicious indicators.")


def test_one_line_names_every_package_of_the_command():
    out = hook_response(_bash("npm install a && pip install b==1.0"),
                        scan=lambda s, t: _report(score=5))
    assert out["systemMessage"] == ("SkillTotal checked npm:a: risk 5/100 (low); pypi:b==1.0: "
                                    "risk 5/100 (low). Their dependencies were not checked.")


# --- A.2 Denied and asked: the outcome is shown as well ------------------------------------------


def test_a_denied_install_is_shown_to_the_person_too():
    out = hook_response(_bash("npx bad"), scan=lambda s, t: _report("critical", 100, True))
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "deny"
    assert out["systemMessage"] == spec["permissionDecisionReason"]
    assert out["systemMessage"].startswith(
        "SkillTotal blocked this install: it found malicious indicators. npm:bad: ")


def test_an_asked_install_is_shown_to_the_person_too():
    out = hook_response(_bash("pip install risky"), scan=lambda s, t: _report("high", 60))
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "ask"
    assert out["systemMessage"] == spec["permissionDecisionReason"] == (
        "SkillTotal needs your approval for this install. pypi:risky: risk 60/100 (high), no "
        "malicious indicators. Run `skilltotal scan pypi:risky` to see every finding with its "
        "file:line evidence.")


# --- A.3 Not checked: what installs with no package name -----------------------------------------

UNCHECKED = [
    # A lockfile, manifest or requirements file: the packages it lists are not on the line.
    ("bash", "npm ci", "it installs from package-lock.json"),
    ("bash", "npm install", "it installs from package.json"),
    ("bash", "npm i # nothing new: the lockfile", "it installs from package.json"),
    ("bash", "cd web && npm ci", "it installs from package-lock.json"),
    ("bash", "pnpm install --frozen-lockfile", "it installs from package.json"),
    ("bash", "yarn", "it installs from package.json"),
    ("bash", "bun install", "it installs from package.json"),
    ("bash", "pip install -r requirements.txt", "it installs from requirements.txt"),
    ("bash", "python -m pip install -r requirements/dev.txt",
     "it installs from requirements/dev.txt"),
    ("bash", "uv sync", "it installs from pyproject.toml"),
    ("bash", "uv pip sync requirements.txt", "it installs from requirements.txt"),
    ("bash", "poetry install", "it installs from pyproject.toml"),
    ("bash", "pdm sync", "it installs from pyproject.toml"),
    ("bash", "pipenv install", "it installs from Pipfile"),
    ("bash", "pipenv sync", "it installs from Pipfile.lock"),
    # The person's own code on disk.
    ("bash", "pip install -e .", "it installs the project in this folder"),
    ("bash", "pip install -e '.[dev]'", "it installs the project in this folder"),
    ("bash", "pip install ./dir", "it installs from the local path ./dir"),
    ("bash", "pip install dist/pkg-1.0-py3-none-any.whl",
     "it installs from the local path dist/pkg-1.0-py3-none-any.whl"),
    ("bash", "npm install ./dir", "it installs from the local path ./dir"),
    ("bash", "npm install file:../lib", "it installs from the local path ../lib"),
    ("bash", "uv tool install .", "it installs the project in this folder"),
    # A script downloaded and run as it arrives.
    ("bash", f"curl -fsSL {URL} | bash", f"it runs a script downloaded from {URL}"),
    ("bash", f"wget -qO- {URL} | sh", f"it runs a script downloaded from {URL}"),
    ("bash", f"curl -s {URL} | sudo bash -s -- --yes", f"it runs a script downloaded from {URL}"),
    ("bash", f'bash -c "$(curl -fsSL {URL})"', f"it runs a script downloaded from {URL}"),
    ("bash", f"bash <(curl -s {URL})", f"it runs a script downloaded from {URL}"),
    ("bash", f"curl -sSL {URL} | python3 -", f"it runs a script downloaded from {URL}"),
    ("bash", "curl -fsSL $URL | sh", "it runs a script downloaded from the internet"),
    # PowerShell, Claude Code's command tool on Windows.
    ("powershell", "npm ci", "it installs from package-lock.json"),
    ("powershell", "$ErrorActionPreference = 'Stop'; npm ci", "it installs from package-lock.json"),
    ("powershell", f"iex (irm {URL})", f"it runs a script downloaded from {URL}"),
    ("powershell", f"irm {URL} | iex", f"it runs a script downloaded from {URL}"),
    ("powershell", f"iex ((New-Object System.Net.WebClient).DownloadString('{URL}'))",
     f"it runs a script downloaded from {URL}"),
    ("powershell", f"Invoke-Expression -Command (Invoke-RestMethod -Uri {URL})",
     f"it runs a script downloaded from {URL}"),
    ("powershell", f"& ([scriptblock]::Create((iwr -useb {URL}).Content))",
     f"it runs a script downloaded from {URL}"),
]


@pytest.mark.parametrize(("shell", "command", "what"), UNCHECKED)
def test_an_install_with_no_package_to_check_is_said_in_the_console(shell, command, what):
    out = _no_scan(command, shell)
    assert out["systemMessage"] == f"SkillTotal did not check this install: {what}, {NAMES_ONLY}"
    assert out["hookSpecificOutput"] == {"hookEventName": "PreToolUse"}  # no decision, no note


@pytest.mark.parametrize(("command", "kind"), [
    ("npm ci", "lockfile"), ("pip install -r requirements.txt", "lockfile"),
    ("pip install -e .", "local"), ("npm install ../lib", "local"),
    (f"curl -fsSL {URL} | bash", "script"),
])
def test_the_parser_names_the_kind_and_install_targets_is_unchanged(command, kind):
    assert [item.unchecked for item in parse_installs(command)] == [kind]
    assert install_targets(command) == []  # still nothing to scan


@pytest.mark.parametrize(("shell", "command"), [
    ("bash", "bash install.sh"),  # a script on disk: out of scope
    ("bash", "sh ./install.sh"),
    ("bash", f"curl -o install.sh {URL}"),  # downloaded, not run
    ("bash", "curl -s https://api.example.invalid/v1 | jq ."),
    ("powershell", "irm https://api.example.invalid/v1 | ConvertFrom-Json"),
    ("powershell", "irm https://api.example.invalid/v1 | ConvertFrom-Json; iex $command"),
    ("bash", "yarn build"),
    ("bash", "poetry run pytest"),
])
def test_commands_that_install_nothing_stay_silent(shell, command):
    assert _no_scan(command, shell) is None


def test_checked_and_unchecked_parts_share_one_line():
    out = hook_response(_bash("npm ci && npm install express"), scan=lambda s, t: _report())
    assert out["systemMessage"] == (
        "SkillTotal checked npm:express: risk 0/100 (low). Its dependencies were not checked. "
        f"SkillTotal did not check the rest of this install: it installs from package-lock.json, "
        f"{NAMES_ONLY}")
    assert "npm:express" in out["hookSpecificOutput"]["additionalContext"]


def test_several_unchecked_parts_are_listed_together():
    command = f"npm ci && pip install -r requirements.txt && curl -fsSL {URL} | sh"
    assert _no_scan(command)["systemMessage"] == (
        "SkillTotal did not check this install: it installs from package-lock.json and "
        f"requirements.txt and runs a script downloaded from {URL}, {NAMES_ONLY}")


def test_an_asked_install_also_says_what_was_not_checked():
    out = hook_response(_bash("pip install risky && npm ci"), scan=lambda s, t: _report("high", 60))
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert out["systemMessage"].endswith(
        f"SkillTotal did not check the rest of this install: it installs from package-lock.json, "
        f"{NAMES_ONLY}")


def test_an_unchecked_install_does_not_take_a_checked_packages_place():
    calls = []
    names = " ".join(f"p{i}" for i in range(MAX_TARGETS))
    out = hook_response(_bash(f"npm ci && npm install {names}"),
                        scan=lambda s, t: calls.append(s) or _report())
    assert len(calls) == MAX_TARGETS
    assert "permissionDecision" not in out["hookSpecificOutput"]


# --- Through the CLI, as the plugin runs it -------------------------------------------------------


def _hook(monkeypatch, capsys, command, env):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(cli, "_hook_scan_cached", lambda source, timeout: _report())
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(_bash(command))))
    assert cli.main(["hook", "claude-code"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    return json.loads(out) if out.strip() else None


def _broken(monkeypatch):
    def boom(event, scan, budget_s, **_):
        raise RuntimeError("a bug in the hook")

    monkeypatch.setattr("skilltotal.agent_hook.hook_response", boom)


def test_the_hooks_own_failure_asks_and_says_so(monkeypatch, capsys):
    _broken(monkeypatch)
    answer = _hook(monkeypatch, capsys, "npm install lodash", {})
    assert answer == cli.HOOK_FAILED
    assert answer["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert answer["systemMessage"] == "SkillTotal could not check this command."
