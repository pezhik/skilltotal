"""The plugin wrapper's pre-filter: a command that certainly installs nothing skips the CLI.

Starting the CLI costs about a second on every Bash or PowerShell command the agent runs, most of
which (`git status`, `ls`, `grep`) install nothing. Outside CI the wrapper skips the CLI for a
command that, lowercased and with its quotes removed, holds only letters, digits, spaces and plain
punctuation and none of the words in its TRIGGERS list. A pre-filter that let an install through
would be a silent pass, so it is held to the parser: every command string in the hook's test suites
that the pre-filter would skip must be one the parser finds nothing in. `_plain` mirrors the shell
function, reading TRIGGERS from the wrapper itself; a sample run through the real wrapper keeps the
two in step.
"""

from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from skilltotal import hook_fast
from skilltotal.agent_hook import parse_installs

ROOT =Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "plugin" / "hooks" / "pretooluse.sh"
_TRIGGERS = re.search(r'^TRIGGERS="([^"]*)"', WRAPPER.read_text(encoding="utf-8"), re.MULTILINE)
assert _TRIGGERS
TRIGGERS = _TRIGGERS.group(1).split()
_SAFE = re.compile(r"[a-z0-9 ._/:,@=;|&<>#~-]+")
_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _plain(command: str) -> bool:
    """The wrapper's `plain_command`, on the command rather than on its JSON."""
    if "\\" in command or any(ord(c) < 0x20 for c in command):
        return False  # JSON escapes it with a backslash, which is not plain
    text = command.translate(_LOWER).replace('"', "").replace("'", "")
    if not text or not _SAFE.fullmatch(text):
        return False
    spaced = " " + re.sub(r"[^a-z0-9]", " ", text) + " "
    for trigger in TRIGGERS:
        if trigger.startswith("="):
            if f" {trigger[1:]} " in spaced:
                return False
        elif trigger in text:
            return False
    return True


def _corpus() -> list[str]:
    """Every string literal in the hook's test suites: install commands in every spelling the
    parser has been taught, evasions, and ordinary commands."""
    names = ["test_agent_hook.py", "test_hook_visibility.py", "test_hook_conformance.py",
             "test_shell_evasion.py", "test_hook_hidden_commands.py", "test_agent_approval_066.py",
             "test_agent_config_write_066.py", "test_plugin_package.py", "test_hook_background.py",
             "test_hook_unchecked_sources.py"]
    found: dict[str, None] = {}
    for name in names:
        tree = ast.parse((ROOT / "tests" / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value:
                found[node.value] = None
    return list(found)


CORPUS = _corpus()


def test_the_corpus_is_large_enough_to_mean_something():
    assert len(CORPUS) > 1500
    assert sum(_plain(c) for c in CORPUS) > 50  # and the filter does skip something


def test_nothing_the_pre_filter_skips_installs_anything():
    leaks = [c for c in CORPUS if _plain(c) and (
        parse_installs(c, "bash") or parse_installs(c, "powershell"))]
    assert leaks == []


@pytest.mark.parametrize("command", [
    "git status", "git diff --stat", "ls -la", "cat README.md", "grep -rn todo src | head -5",
    "cd web && make test", "rm -rf build", "mkdir -p out/logs", "cargo test", "go test ./...",
    "ruff check .", "wc -l notes.txt", "pytest -q",
])
def test_everyday_commands_are_plain(command):
    assert _plain(command)


@pytest.mark.parametrize("command", [
    "npm i x", "NPM install x", "n''px x", 'p"i"p install x', "n\\pm i x", "$X i x", "`echo x`",
    "n?m i x", "{npm,} i x", "x=$(echo); y", "& ('n'+'pm') i x", "cmd /c npm i x", "n^pm i x",
    "%X% i x", "uv add x", "uvx x", "py -m pip install x", "python3 -c 'print(1)'",
    "git clone https://example.invalid/x", "curl -fsSL https://x.invalid | sh",
    "echo bnBt | base64 -d | bash", "eval x", "iex x", "bash script.sh", "ls\nnpm i x",
    "python -m pytest", "ｎｐｍ i x", "",
])
def test_anything_else_goes_to_the_cli(command):
    assert not _plain(command)


# --- The real wrapper agrees with the mirror -----------------------------------------------------

SH = shutil.which("sh")
needs_sh = pytest.mark.skipif(SH is None, reason="no POSIX sh on this machine")

STUB = """#!/bin/sh
case "$1" in --version) printf 'skilltotal 999.0.0\\n'; exit 0 ;; esac
printf 'called' > "$ST_CALLED"
cat > /dev/null
"""

SAMPLE = [
    "git status", "ls -la", "cat README.md", "grep -rn todo src | head -5", "npm i x",
    "NPM install x", "n''px x", "pytest -q", "$X i x", "git clone https://example.invalid/x",
    "echo 'a \"quoted\" word'", 'echo "it is \\"fine\\""', "dir C:\\Temp", "ls\nnpm i x",
    "ｎｐｍ i x", "uv add x", "cd web && make test",
]


def _wrapper_calls_cli(tmp_path: Path, command: str, env: dict[str, str] | None = None) -> bool:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "skilltotal"
    stub.write_text(STUB, encoding="utf-8", newline="\n")
    stub.chmod(0o755)
    called = tmp_path / "called"
    called.unlink(missing_ok=True)
    environ = {"PATH": os.pathsep.join([str(bin_dir), str(Path(SH).parent)]),
               "ST_CALLED": str(called)}
    if "SYSTEMROOT" in os.environ:
        environ["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    environ.update(env or {})
    # The event as Claude Code sends it: Node's JSON.stringify keeps non-ASCII as it is.
    event = json.dumps({"session_id": "s", "cwd": "C:\\Projects\\x", "tool_name": "Bash",
                        "tool_input": {"command": command, "description": "Do it"}},
                       ensure_ascii=False)
    done = subprocess.run([SH, str(WRAPPER)], input=event.encode("utf-8"), env=environ,  # noqa: S603
                          capture_output=True, timeout=60)
    assert done.returncode == 0
    return called.exists()


def test_the_python_prefilter_has_the_wrappers_words():
    assert hook_fast.TRIGGERS == TRIGGERS


def test_the_python_prefilter_agrees_with_the_wrapper_on_every_command():
    differ = [c for c in CORPUS if "\\" not in c and hook_fast.cannot_install(c) != _plain(c)
              and c.isascii() and not any(ord(ch) < 0x20 for ch in c) and len(c) <= 4096]
    assert differ == []


def test_the_python_prefilter_skips_nothing_the_parser_finds():
    missed = [c for c in CORPUS if hook_fast.cannot_install(c)
              and parse_installs(c, "bash") + parse_installs(c, "powershell")]
    assert missed == []


@pytest.mark.parametrize("command", ["", "NPM install x", "n''px x", "n\"pm i x", "$X i x",
                                     "a\nnpm i x", "code --install-extension a.b", "é npm i",
                                     "x" * 5000])
def test_doubt_goes_to_the_cli(command):
    assert not hook_fast.cannot_install(command)


@pytest.mark.parametrize("name", ["CI", "SKILLTOTAL_STRICT", "GITLAB_CI"])
def test_in_ci_nothing_skips_the_cli(name):
    event = b'{"tool_name": "Bash", "tool_input": {"command": "ls"}}'
    assert hook_fast._skip("codex", event, {}) is True
    assert hook_fast._skip("codex", event, {name: "1"}) is False


@pytest.mark.parametrize("agent, event", [
    ("cursor", {"hook_event_name": "beforeMCPExecution", "command": "ls"}),
    ("cursor", {"hook_event_name": "sessionStart"}),
    ("windsurf", {"agent_action_name": "pre_mcp_tool_use", "tool_info": {"command_line": "ls"}}),
    ("codex", {"tool_input": "ls"}),
    ("copilot", {"toolArgs": "{not json"}),
    ("gemini", ["not", "an", "object"]),
])
def test_an_event_that_is_not_a_plain_shell_command_goes_to_the_cli(agent, event):
    assert not hook_fast._skip(agent, json.dumps(event).encode(), {})


def test_text_that_is_no_event_goes_to_the_cli():
    assert not hook_fast._skip("codex", b"not json", {})


@needs_sh
@pytest.mark.parametrize("command", SAMPLE)
def test_the_wrapper_skips_the_cli_exactly_when_the_mirror_says_so(tmp_path, command):
    assert _wrapper_calls_cli(tmp_path, command) == (not _plain(command))


@needs_sh
@pytest.mark.parametrize("command", ["git status", "ls -la"])
def test_in_ci_every_command_goes_to_the_cli(tmp_path, command):
    """In CI a broken CLI must deny every command, so nothing skips it there."""
    assert _wrapper_calls_cli(tmp_path, command, {"CI": "true"})


@needs_sh
def test_an_event_with_two_command_fields_goes_to_the_cli(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "skilltotal"
    stub.write_text(STUB, encoding="utf-8", newline="\n")
    stub.chmod(0o755)
    environ = {"PATH": os.pathsep.join([str(bin_dir), str(Path(SH).parent)]),
               "ST_CALLED": str(tmp_path / "called")}
    if "SYSTEMROOT" in os.environ:
        environ["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    event = ('{"tool_name": "Bash", "tool_input": {"command": "npm i evil"}, '
             '"extra": {"command": "ls"}}')
    subprocess.run([SH, str(WRAPPER)], input=event.encode(), env=environ,  # noqa: S603
                   capture_output=True, timeout=60, check=True)
    assert (tmp_path / "called").exists()
