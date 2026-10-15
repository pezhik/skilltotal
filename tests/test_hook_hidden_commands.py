"""Encoded and computed install commands are asked about (denied in CI), never let through silently.

An external audit (2026-10-15) ran these commands through the hook: each one installs `is-number`
or `six` once the shell, Python or PowerShell decodes or builds the command line, and the hook gave
no answer and no console line, even in strict mode. The parser cannot read what a decoder prints,
so the person is asked ("a command SkillTotal could not read"), as the forms that already name an
installer were (`$(echo npm) i x`). Ordinary commands that decode or compute something without
running it as a command stay silent. The base64 below is inert test data; nothing is run.
"""

from __future__ import annotations

import json

import pytest

from skilltotal.agent_hook import GIT_CLONE, hook_response, parse_installs

NOT_READ = "a command SkillTotal could not read"
# `npm i is-number`, and `pip install six`.
NPM_B64 = "bnBtIGkgaXMtbnVtYmVy"
PIP_B64 = "cGlwIGluc3RhbGwgc2l4"


def _event(command: str, shell: str) -> dict:
    tool = "Bash" if shell == "bash" else "PowerShell"
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": {"command": command}}


def _respond(command: str, shell: str = "bash", **options):
    calls: list[str] = []
    out = hook_response(_event(command, shell), scan=lambda s, t: calls.append(s) or {},
                        **options)
    assert calls == []
    return out


HIDDEN = [
    ("bash", f'eval "$(echo {NPM_B64} | base64 -d)"'),
    ("bash", f"eval `echo {NPM_B64} | base64 --decode`"),
    ("bash", f"echo {NPM_B64} | base64 -d | bash"),
    ("bash", f"echo {NPM_B64} | base64 -d | sh"),
    ("bash", f"echo {NPM_B64} | base64 -d | sh -s"),
    ("bash", f"base64 -d <<< {NPM_B64} | bash"),
    ("bash", f'bash -c "$(echo {NPM_B64} | base64 -d)"'),
    ("bash", f'sh -c "$(echo {NPM_B64} | openssl base64 -d)"'),
    ("bash", f'source <(echo {NPM_B64} | base64 -d)'),
    ("bash", 'X=$(printf "\\x6e\\x70\\x6d"); $X i is-number'),
    ("bash", "X=$(printf '\\156\\160\\155'); $X i is-number"),
    ("bash", f'X=$(echo {NPM_B64} | base64 -d); eval "$X"'),
    ("bash", "X=$(cat cmd.txt); $X install is-number"),
    ("bash", "echo 'rebmun-si i mpn' | rev | sh"),
    ("bash", "python -c \"import base64,os; os.system(base64.b64decode('"
             + PIP_B64 + "').decode())\""),
    ("bash", "python3 -c \"import base64,subprocess; subprocess.run(base64.b64decode('"
             + PIP_B64 + "'), shell=True)\""),
    ("bash", "node -e \"require('child_process').execSync(Buffer.from('"
             + NPM_B64 + "','base64').toString())\""),
    ("bash", "node -e \"require('child_process').execSync(atob('" + NPM_B64 + "'))\""),
    ("bash", "perl -e 'use MIME::Base64; system(decode_base64(\"" + NPM_B64 + "\"))'"),
    ("powershell", "iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(\""
                   + NPM_B64 + "\")))"),
    ("powershell", "$s = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
                   + NPM_B64 + "')); iex $s"),
    ("powershell", "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
                   + NPM_B64 + "')) | iex"),
    ("powershell", "Invoke-Expression ([Text.Encoding]::UTF8.GetString("
                   "[Convert]::FromBase64String('" + NPM_B64 + "')))"),
    ("powershell", '$c = "np" + "m"; & $c i is-number'),
    ("powershell", "$c = 'np' + 'm'; & $c install is-number"),
    ("powershell", "$c = -join ('n','p','m'); & $c i is-number"),
    ("powershell", "pwsh -Command \"iex ([Text.Encoding]::UTF8.GetString("
                   "[Convert]::FromBase64String('" + NPM_B64 + "')))\""),
]


@pytest.mark.parametrize(("shell", "command"), HIDDEN)
def test_an_encoded_or_computed_install_is_asked_about(shell, command):
    out = _respond(command, shell)
    assert out is not None, "silent"
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "ask"
    assert NOT_READ in spec["permissionDecisionReason"]
    assert NOT_READ in out["systemMessage"]


@pytest.mark.parametrize(("shell", "command"), HIDDEN)
def test_in_ci_an_encoded_or_computed_install_is_denied(shell, command):
    out = _respond(command, shell, strict=True, strict_by="SKILLTOTAL_STRICT")
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert NOT_READ in out["hookSpecificOutput"]["permissionDecisionReason"]


# Common commands that decode, evaluate or compute something, but run no hidden command line.
ORDINARY = [
    ("bash", "echo $HOME"),
    ("bash", "base64 file.txt"),
    ("bash", "base64 -d secret.b64 > key.bin"),
    ("bash", f"echo {NPM_B64} | base64 -d"),
    ("bash", f"echo {NPM_B64} | base64 -d | less"),
    ("bash", 'eval "$(ssh-agent -s)"'),
    ("bash", 'eval "$(direnv hook bash)"'),
    ("bash", 'eval "$(pyenv init -)"'),
    ("bash", 'eval "$(/opt/homebrew/bin/brew shellenv)"'),
    ("bash", 'eval "$(starship init bash)"'),
    ("bash", "$EDITOR notes.md"),
    ("bash", '"$(command -v python3)" -m py_compile x.py'),
    ("bash", "cat setup.sh | bash"),
    ("bash", "python -c \"import base64; print(base64.b64decode('aGk='))\""),
    ("bash", "node -e \"console.log(Buffer.from('aGk=', 'base64').toString())\""),
    ("bash", 'printf "\\x41\\n"'),
    ("powershell", "[Convert]::FromBase64String('aGk=')"),
    ("powershell", "$p = $env:TEMP + '\\x'; Get-ChildItem $p"),
    ("powershell", "& $exe --version"),
    ("powershell", "Get-Content .\\setup.ps1 | iex"),
]


@pytest.mark.parametrize(("shell", "command"), ORDINARY)
def test_ordinary_decoding_and_shell_init_stay_silent(shell, command):
    assert parse_installs(command, shell) == []


@pytest.mark.parametrize("command", [
    "node -e '" + "Buffer.from(" * 20_000 + "'",
    "X=1; $X " + "'" + " " * 100_000 + "'",
    "eval \"$(" + "atob " * 20_000 + ")\"",
], ids=["buffer-from", "spaces", "atob"])
def test_reading_for_hidden_commands_stays_linear(command):
    """The hook reads every command the agent runs; a crafted one must not stall it."""
    import time

    start = time.perf_counter()
    parse_installs(command)
    assert time.perf_counter() - start < 5


# --- git clone: not checked, and said so -------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "shown"),
    [
        ("git clone https://github.com/example/tool", "https://github.com/example/tool"),
        ("git clone --depth 1 -b main https://github.com/example/tool.git dir",
         "https://github.com/example/tool.git"),
        ("git -C /tmp clone git@github.com:example/tool.git", "a git repository"),
        ("cd /tmp && git clone https://gitlab.example.invalid/x/y", "https://gitlab.example.invalid/x/y"),
    ],
)
def test_a_git_clone_gets_a_console_line_saying_it_is_not_checked(command, shown):
    out = _respond(command)
    assert out is not None
    assert "permissionDecision" not in out["hookSpecificOutput"]
    message = out["systemMessage"]
    assert message.startswith("SkillTotal did not check this command:")
    assert shown in message


def test_a_git_clone_is_not_denied_in_ci():
    out = _respond("git clone https://github.com/example/tool", strict=True, strict_by="CI")
    assert "permissionDecision" not in out["hookSpecificOutput"]
    assert "did not check this command" in out["systemMessage"]


def test_a_git_clone_is_its_own_kind():
    (item,) = parse_installs("git clone https://github.com/example/tool")
    assert item.unchecked == GIT_CLONE


@pytest.mark.parametrize("command", ["git status", "git log --oneline", "git clone --help"])
def test_other_git_commands_stay_silent(command):
    assert parse_installs(command) == []


# --- Echoed names are capped ---------------------------------------------------------------------


def test_a_huge_package_name_does_not_produce_a_huge_answer():
    """Seen in the audit: a 200,000-character name came back three times, 600 KB of hook JSON."""
    name = "a" * 200_000
    out = hook_response(_event(f"npm i {name}", "bash"),
                        scan=lambda s, t: {"risk_level": "high", "risk_score": 80,
                                           "verdict": {"has_malicious_indicators": False}})
    assert len(json.dumps(out)) < 4_000
    assert "aaaa" in out["systemMessage"]


def test_a_huge_unverifiable_spec_is_capped_but_keeps_its_reason():
    spec = "https://example.invalid/" + "b" * 50_000 + ".tgz"
    out = _respond(f"npm i {spec}")
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert len(reason) < 1_000
    assert "(a remote archive or repository)" in reason


# --- Security review 2026-10-15, H3: commands the parser did not take apart ---------------------

# PowerShell's call operator in front of an expression: the command is computed when the line runs.
COMPUTED_CALLS = [
    "& (gcm npm) i evilx",
    "& (Get-Command npm) install evilx",
    "& (Get-Command npm).Path i evilx",
    "& (gcm npm).Source i evilx",
    "& ('n'+'pm') i evilx",
    "& ('np' + 'm') install evilx",
    "& (Join-Path $env:ProgramFiles 'nodejs\\npm.cmd') i evilx",
    "& (where.exe npm | select -first 1) i evilx",
    "& (which npm) i evilx",
    "& $(gcm npm) i evilx",
    ". (gcm npm) i evilx",
    "& (gcm npx) -y evilx",
    "& (gcm pip) install evilx",
    "& (Get-Command -Name npm -CommandType Application) add evilx",
    "& (Get-Variable -ValueOnly x) i evilx",
]


@pytest.mark.parametrize("command", COMPUTED_CALLS)
def test_a_command_powershell_computes_is_asked_about(command):
    out = _respond(command, "powershell")
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert NOT_READ in out["hookSpecificOutput"]["permissionDecisionReason"]
    strict = _respond(command, "powershell", strict=True, strict_by="CI")
    assert strict["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("command", [
    "& (gcm python) --version",
    "& (Join-Path $PSScriptRoot 'build.ps1') -Release",
    "$x = (Get-Date).AddDays(1)",
    "& ($env:EDITOR) notes.md",
    ". (Join-Path $HOME 'profile.ps1')",
])
def test_a_computed_call_that_installs_nothing_stays_silent(command):
    assert parse_installs(command, "powershell") == []


# Programs that run the command they are given: what that command installs is checked.
WRAPPED = [
    ("corepack pnpm@9 add evilx", "npm:evilx"),
    ("corepack yarn@1.22.22 add evilx", "npm:evilx"),
    ("corepack npm@10.8.0 i evilx", "npm:evilx"),
    ("pnpm --package=evilx dlx y", "npm:evilx"),
    ("pnpm --package evilx dlx y", "npm:evilx"),
    ("npm --package=evilx exec -- y", "npm:evilx"),
    ("volta run npm i evilx", "npm:evilx"),
    ("volta run --node 20 npx evilx", "npm:evilx"),
    ("nvm exec 20 npm i evilx", "npm:evilx"),
    ("fnm exec --using=20 npm i evilx", "npm:evilx"),
    ("cross-env NODE_ENV=production npm i evilx", "npm:evilx"),
    ("npx cross-env A=1 npm i evilx", "npm:evilx"),
    ("aws-vault exec prod -- npm i evilx", "npm:evilx"),
    ("mise use -g npm:evilx", "npm:evilx"),
    ("mise install npm:evilx@1.2.3", "npm:evilx@1.2.3"),
    ("mise use -g pipx:evilx", "pypi:evilx"),
]


@pytest.mark.parametrize(("command", "source"), WRAPPED)
def test_what_a_wrapped_command_installs_is_checked(command, source):
    assert source in [i.source for i in parse_installs(command)]


def test_pnpm_package_in_front_of_dlx_checks_both_names():
    assert [i.source for i in parse_installs("pnpm --package=evilx dlx y")] == [
        "npm:evilx", "npm:y"]


# Programs that run the command with variables loaded from somewhere the hook does not read (a
# .env or .envrc, a secrets manager, a tool's configuration, WSL's own home): a registry can be
# set there, so the package is asked about like one from a configured registry.
ENV_LOADERS = [
    ("bash", "dotenv -- npm i evilx"),
    ("bash", "dotenv -e .env.local -- npx -y evilx"),
    ("bash", "direnv exec . npm i evilx"),
    ("bash", "op run --env-file=.env -- npm i evilx"),
    ("bash", "doppler run -- pip install evilx"),
    ("bash", "devbox run npm i evilx"),
    ("bash", "nix-shell -p nodejs --run 'npm i evilx'"),
    ("bash", "mise exec node@20 -- npm i evilx"),
    ("bash", "mise x -- npx evilx"),
    ("bash", "mise exec npm:evilx -- evilx"),
    ("powershell", "wsl npm i evilx"),
    ("powershell", "wsl -e npm i evilx"),
    ("powershell", "wsl -- npm i evilx"),
    ("powershell", "wsl.exe -d Ubuntu -e bash -c 'npm i evilx'"),
    ("bash", "wsl bash -c 'npm i evilx'"),
]


@pytest.mark.parametrize(("shell", "command"), ENV_LOADERS)
def test_a_command_run_with_loaded_variables_is_asked_about(shell, command):
    out = _respond(command, shell)
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "evilx from a registry the environment " in reason
    strict = _respond(command, shell, strict=True, strict_by="CI")
    assert strict["hookSpecificOutput"]["permissionDecision"] == "deny"
    allowed = _respond(command, shell, strict=True, strict_by="CI",
                       allow_unchecked=frozenset({"registry"}))
    assert allowed["hookSpecificOutput"].get("permissionDecision") != "deny"


UNKNOWN_RUNNERS = [
    "with-env npm i evilx",
    "retry -t 3 -- npm install evilx",
    "lerna exec -- npm i evilx",
    "some-tool run uvx evilx",
    "npx some-runner npm i evilx",
]


@pytest.mark.parametrize("command", UNKNOWN_RUNNERS)
def test_an_unknown_program_given_an_install_command_is_asked_about(command):
    """In CI a line that installs through a program the hook does not know is denied; outside
    CI the person is asked. The package it names is still checked."""
    calls: list[str] = []
    clean = {"risk_level": "low", "risk_score": 0, "findings": [],
             "verdict": {"has_malicious_indicators": False}}
    out = hook_response(_event(command, "bash"), scan=lambda s, t: calls.append(s) or clean)
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "a program SkillTotal does not know" in out["hookSpecificOutput"][
        "permissionDecisionReason"]
    assert "npm:evilx" in calls or "pypi:evilx" in calls
    strict = hook_response(_event(command, "bash"), scan=lambda s, t: clean, strict=True,
                           strict_by="CI")
    assert strict["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("command", [
    "echo npm i evilx",
    "grep -rn npm install docs",
    "which npm",
    "git commit -m 'npm i evilx'",
    "docker run --rm node:22 npm ci",
    "ssh build-host npm i evilx",
    "nvm use 20",
    "nvm install 20",
    "volta pin node@20",
    "op item get npm",
    "mise use node@20",
    "kill npm",
    "some-tool npm",
    "nodemon --exec 'npm start'",
])
def test_an_installer_named_where_it_does_not_run_stays_silent(command):
    assert parse_installs(command) == []
