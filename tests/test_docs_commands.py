"""Every `skilltotal ...` command the README and docs show parses with the real CLI parser.

Readers copy these lines into terminals and pipelines. A renamed flag, a removed subcommand or a
choice that no longer exists (`--fail-on hihg`) must fail here, not in a customer's build. The
commands are parsed with :func:`skilltotal.cli.build_parser`, never run.
"""

from __future__ import annotations

import contextlib
import io
import re
import shlex
from pathlib import Path

import pytest

from skilltotal.cli import build_parser

ROOT = Path(__file__).resolve().parent.parent
DOCS = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
_BLOCK = re.compile(r"^```(?:bash|sh|shell|console)[ \t]*\n(.*?)^```", re.M | re.S)
_PROMPT = re.compile(r"^(?:\$|>)\s+")
_PLACEHOLDER = re.compile(r"<[^<>\s][^<>]*>")
_SHELL_OPERATORS = {"&&", "||", "|", ";", ">", ">>", "2>", "2>&1"}


def _documented_commands() -> list[tuple[str, str]]:
    commands = []
    for path in DOCS:
        text = path.read_text(encoding="utf-8")
        for block in _BLOCK.finditer(text):
            first_line = text.count("\n", 0, block.start(1)) + 1
            # Join `\` continuations, keeping the line number of the first physical line.
            logical: list[tuple[int, str]] = []
            pending, start = "", first_line
            for offset, line in enumerate(block.group(1).splitlines()):
                if not pending:
                    start = first_line + offset
                if line.rstrip().endswith("\\"):
                    pending += line.rstrip()[:-1] + " "
                    continue
                logical.append((start, pending + line))
                pending = ""
            for line_no, line in logical:
                command = _PROMPT.sub("", line.strip())
                if command.startswith("skilltotal "):
                    commands.append((f"{path.relative_to(ROOT).as_posix()}:{line_no}", command))
    return commands


COMMANDS = _documented_commands()


def _argv(command: str) -> list[str]:
    # A placeholder (`<path>`) stands for a value the reader supplies: a dummy must parse in its
    # place, so a placeholder never hides a flag or subcommand that does not exist.
    command = _PLACEHOLDER.sub("placeholder", command)
    words = shlex.split(command, comments=True)
    for index, word in enumerate(words):
        if word in _SHELL_OPERATORS:
            words = words[:index]
            break
    assert words[0] == "skilltotal"
    return words[1:]


def test_the_docs_show_commands():
    assert len(COMMANDS) >= 40, f"only {len(COMMANDS)} documented commands found"
    subcommands = {_argv(command)[0] for _, command in COMMANDS}
    assert {"scan", "diff", "guard", "inventory", "rules"} <= subcommands, subcommands


@pytest.mark.parametrize(("where", "command"), COMMANDS, ids=[where for where, _ in COMMANDS])
def test_documented_command_parses(where, command):
    argv = _argv(command)
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            build_parser().parse_args(argv)
    except SystemExit as exc:
        # --version and --help exit 0 after printing; a usage error exits 1.
        assert exc.code == 0, f"{where}: `{command}` does not parse: {err.getvalue().strip()}"
