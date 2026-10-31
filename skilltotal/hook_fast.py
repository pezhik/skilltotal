"""The ``skilltotal`` entry point, and a way past the CLI for what certainly installs nothing.

An agent's hook runs before every shell command, and most of them (``git status``, ``ls``) install
nothing. Importing the CLI costs more than Python's own start, so a command that cannot install
anything is answered here, with nothing imported but ``json``. Claude Code's plugin does the same in
``plugin/hooks/pretooluse.sh``. These hooks cannot use that script: Cursor runs its hooks through
PowerShell on Windows, and no ``sh`` is promised there.

The test is the wrapper's, and ``tests/test_plugin_prefilter.py`` holds both to the parser and to
each other: only ASCII letters, digits, spaces, quotes and plain punctuation (nothing a shell can
build a name from), and, with quotes removed and in any letter case, none of the trigger words.
Anything else, any event this cannot read, and everything in CI goes to the CLI.
"""

from __future__ import annotations

import io
import os
import sys

# What an agent's hook answers when it has nothing to say: see agent_adapters.
_CURSOR_NEUTRAL = 1
_AGENTS = ("cursor", "windsurf", "devin", "codex", "gemini", "copilot")
_CI_MARKERS = ("SKILLTOTAL_STRICT", "CI", "TF_BUILD", "JENKINS_URL", "TEAMCITY_VERSION",
               "CODEBUILD_BUILD_ID", "BUILDKITE", "GITLAB_CI")
# The wrapper's TRIGGERS. A word with `=` in front must stand alone; the others count anywhere.
TRIGGERS = (
    "np bun yarn pip =uv =uvx poetry pdm pipenv corepack conda mamba rye pixi volta easy_install "
    "deno hatch tox nox python =py =py2 =py3 node perl ruby php osascript "
    "=sh bash zsh dash ksh fish pwsh powershell cmd =exec eval iex invoke source trap alias "
    "curl wget =irm =iwr download webclient http base xxd openssl printf decode atob uudecode "
    "clone claude codex gemini skill smithery mcp extension"
).split()
_ANYWHERE = tuple(word for word in TRIGGERS if not word.startswith("="))
_ALONE = tuple(word[1:] for word in TRIGGERS if word.startswith("="))
_LETTERS = "abcdefghijklmnopqrstuvwxyz0123456789"
_PLAIN = frozenset(_LETTERS + " ._/:,@=;|&<>#~-")
_MAX_COMMAND = 4096


def cannot_install(command: str) -> bool:
    """Whether ``command`` certainly installs nothing. Any doubt answers no."""
    if not command or len(command) > _MAX_COMMAND or not command.isascii():
        return False
    text = command.lower().replace('"', "").replace("'", "")
    if not text or not _PLAIN.issuperset(text):
        return False
    if any(word in text for word in _ANYWHERE):
        return False
    words = "".join(c if c in _LETTERS else " " for c in text).split()
    return not any(word in words for word in _ALONE)


def shell_command(agent: str, event: object) -> str | None:
    """The shell command of an agent's hook event, or None for any other event."""
    if not isinstance(event, dict):
        return None
    if agent == "cursor":
        value = event.get("command") if event.get("hook_event_name") == "beforeShellExecution" \
            else None
    elif agent == "windsurf":
        info = event.get("tool_info")
        value = info.get("command_line") if event.get("agent_action_name") == "pre_run_command" \
            and isinstance(info, dict) else None
    elif agent == "copilot":
        import json

        args = event.get("toolArgs", event.get("tool_input"))
        try:
            args = json.loads(args) if isinstance(args, str) else args
        except ValueError:
            return None
        value = args.get("command") if isinstance(args, dict) else None
    else:
        args = event.get("tool_input")
        value = args.get("command") if isinstance(args, dict) else None
    return value if isinstance(value, str) else None


def _skip(agent: str, raw: bytes, environ: dict[str, str] | os._Environ[str]) -> bool:
    import json

    if any(environ.get(name) for name in _CI_MARKERS):
        return False
    try:
        command = shell_command(agent, json.loads(raw.decode("utf-8")))
    except (ValueError, RecursionError):
        return False
    return command is not None and cannot_install(command)


def main() -> int:
    argv = sys.argv[1:]
    if len(argv) >= 2 and argv[0] == "hook" and argv[1] in _AGENTS and argv[2:] in (
            [], ["--fail-closed"]):
        raw = sys.stdin.buffer.read()
        if _skip(argv[1], raw, os.environ):
            if argv[1] != "cursor":
                return 0
            if argv[2:]:
                print('{"permission": "allow"}')
                return 0
            return _CURSOR_NEUTRAL
        sys.stdin = io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8")
    from skilltotal.cli import main as cli_main

    return cli_main()
