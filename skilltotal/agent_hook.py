"""Claude Code PreToolUse hook: check a package before the agent installs it.

The SkillTotal plugin runs this before every Bash or PowerShell command the agent wants to execute
(Claude Code on Windows runs most commands through its PowerShell tool). It finds the
packages an install command would bring in (``npx``, ``npm install``, ``pip install``, ``uvx``,
``claude mcp add ... -- npx ...``), scans each one, and answers in Claude Code's hook format:

* a package with malicious indicators: ``deny``, with the reason shown to the agent;
* a package whose scored risk is high or critical: ``ask``, so the person decides;
* a package the scanner cannot see (a custom registry or index, a remote archive): ``ask``,
  because scanning the public copy would vouch for code that is not the code being installed;
* a package that was not checked (the scan failed or ran out of time, or the command names more
  packages than one check covers): ``ask``. Letting it through would make the guard easy to step
  around: pad a package until its scan times out, or name it sixth;
* everything clean: no decision (the normal permission flow applies) plus a one-line note for the
  agent.

The hook never denies for its own failure: the person decides, and the install goes ahead if they
approve. The parser errs toward finding installs: a shell that would install a package must not
slip past it through a global flag, a full path, a wrapper (``bash -c``, ``sudo``, ``env``,
``timeout``...), a command substitution or an alias of the subcommand. It reads the command line
the way the shell does (quotes, escapes, line continuations, comments, here-documents), and a
command it cannot read that names an installer is asked about rather than let through. It is still
a static reading of a command line, a guardrail rather than a sandbox. Pure library code: the CLI
reads stdin and prints the answer.
"""

from __future__ import annotations

import base64
import binascii
import functools
import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from skilltotal.guard import PLAIN_PATH, evaluate, unanalyzed_install_scripts

# How many packages one command gets checked; the person is asked about the rest.
MAX_TARGETS = 5
# How long the agent waits for all checks of one command. A large package can take longer to scan
# than anyone will wait before every install; past this the person is asked instead.
DEFAULT_BUDGET_S = 20.0
_MAX_DEPTH = 4  # nested `bash -c "$(...)"`; deeper than this is not an honest install command
# Quotes and substitutions nested deeper than this inside one command line are not read.
_MAX_NESTING = 64
# Where a wrapper's command may start (`claude mcp add`, `watch`): the places tried, at most.
_MAX_LAUNCHES = 16


@dataclass(frozen=True)
class Install:
    """One thing an install command brings in: a scannable ``source``, or why it cannot be one."""

    source: str | None
    unverifiable: str | None = None  # e.g. "pkg from https://registry.example"


# Text the hook could not take apart as commands, when it names an installer.
_NOT_READ = Install(None, "a command SkillTotal could not read")
# Stands in for a command substitution among a command's words: what it prints is not known here.
_SUB = "$(...)"
# An installer and an install-like verb near it: read in text that runs but that the parser could
# not split into commands (an unclosed quote, code in another language, a script piped to a shell).
_INSTALL_WORDS = re.compile(
    r"(?<![\w.-])(?:(?:npx|bunx|pnpx|uvx|pipx)(?![\w.-])"
    r"|(?:npm|pnpm|yarn|bun|pip[0-9.]*|uv|poetry|pdm|pipenv)(?![\w.-])[^\n;&|]{0,80}?"
    r"(?<![\w.-])(?:install|isntall|i|in|it|add|create|init|innit|exec|x|dlx|tool|run)(?![\w.-]))",
    re.IGNORECASE,
)
# A word the shell fills in when it runs: a variable, a substitution, a brace expansion.
_COMPUTED = re.compile(r"[$`{}]")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# A file path a reason may quote: no whitespace or punctuation a sentence needs (see guard).
_PLAIN_PATH = PLAIN_PATH
# A version the reason may quote; it comes from the scanned manifest, so it is held to the same.
_PLAIN_VERSION = re.compile(r"[0-9][0-9A-Za-z.+-]{0,40}")
_DRIVE = re.compile(r"^[A-Za-z]:")
_PY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")
# An exact version the registry can serve as is: npm `1.2.3` / `1.2.3-beta.1` or a dist-tag
# (`latest`, `next`); PyPI `==2.31.0` (no wildcard). Anything else is a range for the installer.
_NPM_EXACT = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?|[A-Za-z][\w.-]*")
_PY_EXACT = re.compile(r"\s*==\s*([0-9][0-9A-Za-z.+!-]*)\s*$")
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$", re.IGNORECASE)
# `alias@npm:real@1.2.3` installs `real` under the name `alias`.
_NPM_ALIAS = re.compile(r"^(?:@[^/@\s]+/)?[^@\s]+@npm:(\S+)$")
# npm's shorthands for repositories on other git hosts, which the hook does not fetch.
_NPM_OTHER_HOSTS = ("gist:", "bitbucket:", "gitlab:")
_GH_SHORTHAND = re.compile(
    r"^(?:github:)?([A-Za-z0-9][\w.-]*)/([A-Za-z0-9][\w.-]*?)(?P<tail>#.*)?$")
_GH_URL = re.compile(r"^(?:git\+)?(?:https?|ssh|git)://(?:[^@/]+@)?github\.com[/:]"
                     r"([\w.-]+)/([\w.-]+?)(?:\.git)?(?P<tail>[@#].*?)?/?$")
# A branch, tag or commit the scan can check out exactly as the installer will.
_PLAIN_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
# A URL fragment that is pip metadata (`#egg=name&subdirectory=pkg`), not a git ref.
_PIP_FRAGMENT = re.compile(
    r"(?:egg|subdirectory|sha1|sha224|sha256|sha384|sha512|md5)=[^&#]*"
    r"(?:&(?:egg|subdirectory|sha1|sha224|sha256|sha384|sha512|md5)=[^&#]*)*"
)

# Wrappers that run the rest of the line as a command, with the flags of theirs that take a value.
_WRAPPERS: dict[str, set[str]] = {
    "sudo": {"-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-D"},
    "doas": {"-u", "-C"},
    "env": {"-u", "-C", "-S", "--unset", "--chdir"},
    "exec": {"-a"},
    "nohup": set(),
    "time": {"-f", "-o"},
    "command": set(),
    "builtin": set(),
    "nice": {"-n"},
    "stdbuf": {"-i", "-o", "-e"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
}
# Shell keywords that can stand in front of a command: `if npm i x; then`, `! npm i x`.
_KEYWORDS = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "{", "coproc"})
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}
# PowerShell: wrappers that take the command line as a string, and the ones that start a program.
_PS_EVAL = {"iex", "invoke-expression"}
_PS_START = {"start-process", "saps", "start"}
_PIP_HEAD = re.compile(r"pip\d*(?:\.\d+)?")
_PYTHON_HEAD = re.compile(r"(?:python|py)\d*(?:\.\d+)?")

# npm-family subcommands that install the named packages (npm's own aliases and typo-tolerance).
_NPM_INSTALL = {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal",
                "isntall", "add", "install-test", "it"}
_NPM_RUNNERS = {"npx", "bunx", "pnpx"}
# Global flags of a package manager that take a value (so the value is not the subcommand).
_NPM_VALUE_FLAGS = {"--registry", "--prefix", "--cache", "--tag", "-w", "--workspace",
                    "--userconfig", "--globalconfig", "-C", "--dir", "--cwd", "--filter", "-F",
                    "--loglevel", "--location", "--before", "--otp", "-p", "--package"}
_PIP_VALUE_FLAGS = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i",
                    "--index-url", "--extra-index-url", "-t", "--target", "--prefix", "-f",
                    "--find-links", "--python", "--root", "--platform", "--python-version",
                    "--log", "--cache-dir", "--proxy", "--retries", "--timeout", "--src",
                    "--upgrade-strategy", "--implementation", "--abi", "--progress-bar",
                    "-C", "--config-settings", "--global-option", "--only-binary", "--no-binary",
                    "--trusted-host", "--cert", "--client-cert", "--exists-action",
                    "--use-feature", "--use-deprecated", "--keyring-provider", "--report",
                    "--root-user-action"}
_UV_VALUE_FLAGS = {"--python", "-p", "--with", "--index", "--index-url", "--extra-index-url",
                   "--default-index", "--group", "--extra", "--package", "--directory",
                   "--project", "--cache-dir", "--config-file", "--color", "-f", "--find-links",
                   "--from", "--with-editable", "--with-requirements"}
_PY_VALUE_FLAGS = {"-X", "-W", "-c"}
# Flags that make the package come from somewhere the public-registry scan does not cover.
_NPM_SOURCE_FLAGS = {"--registry"}
_PIP_SOURCE_FLAGS = {"-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--index",
                     "--default-index"}


def install_targets(command: str, shell: str = "bash") -> list[str]:
    """Scannable sources (``npm:name``, ``pypi:name``, a GitHub URL) an install would bring in."""
    return [i.source for i in parse_installs(command, shell) if i.source]


def parse_installs(command: str, shell: str = "bash", _depth: int = 0) -> list[Install]:
    """Everything an install command would bring in, scannable or not.

    ``shell`` is how the command line is quoted: ``bash`` (POSIX), ``powershell`` or ``cmd``.
    """
    return _parse(command, shell, _depth, _Level(_Context(command)))


@dataclass
class _Context:
    """The command line the hook was given, shared by every reading of the text inside it."""

    root: str


@dataclass(frozen=True)
class _Level:
    """One piece of text read as commands: the whole line, or what a substitution or a
    ``bash -c`` inside it runs, with that piece's command substitutions."""

    ctx: _Context
    subs: tuple[str, ...] = ()


def _parse(text: str, shell: str, depth: int, outer: _Level) -> list[Install]:
    if not text:
        return []
    if depth > _MAX_DEPTH:
        return _net(text)
    text = text.replace("\r\n", "\n")
    try:
        lexed = _Lexer(text, shell).lex()
    except _Unreadable:
        return _net(text)  # the shell would not run it as written; ask if it names an installer
    level = _Level(outer.ctx, tuple(lexed.subs))
    found: dict[Install, None] = {}
    # A command substitution runs too: `echo $(npm install x)` installs x.
    for sub in lexed.subs:
        found.update(dict.fromkeys(_parse(sub, shell, depth + 1, level)))
    for pipeline in lexed.pipelines:
        output: tuple[str, bool] | None = None  # what the previous command writes into this one
        for position, stage in enumerate(pipeline, 1):
            words, strings = _redirects(stage.words)
            feed = [(body, True) for body in (*stage.bodies, *strings)]
            if output is not None:
                feed.append(output)
            found.update(dict.fromkeys(_installs_in(words, shell, depth, level, feed)))
            if position < len(pipeline):
                output = _output_of(words, feed, "".join(stage.text), shell)
    return list(found)


def _net(*texts: str) -> list[Install]:
    """The person is asked about text that runs but could not be read, when it names an
    installer; text that names none stays out of the agent's way."""
    return [_NOT_READ] if any(_INSTALL_WORDS.search(t) for t in texts) else []


def _run(text: str, shell: str, depth: int, level: _Level) -> list[Install]:
    """What a command line another program runs would install (``bash -c``, ``iex``)."""
    return _parse(text, shell, depth + 1, level)


def _words(text: str, shell: str) -> list[str] | None:
    """The words of a short command line (a ``Start-Process`` argument list), or None when it
    does not read."""
    try:
        lexed = _Lexer(text.replace("\r\n", "\n"), shell).lex()
    except _Unreadable:
        return None
    return [word for pipeline in lexed.pipelines for stage in pipeline for word in stage.words]


# --- Reading the command line ----------------------------------------------------------------


class _Unreadable(Exception):
    """The text does not read the way the shell would take it, or nests too deep to read."""


@dataclass
class _Stage:
    """One simple command: its words as the shell passes them, its text (comments, line
    continuations and here-document bodies taken out, each command substitution standing as
    ``$(...)``), and the here-document bodies it reads on stdin."""

    words: list[str] = field(default_factory=list)
    text: list[str] = field(default_factory=list)
    bodies: list[str] = field(default_factory=list)


_ESCAPE = {"bash": "\\", "powershell": "`", "cmd": "^"}
# PowerShell takes typographic quotes as quotes.
_PS_SINGLE = "'‘’‚‛"
_PS_DOUBLE = '"“”„'
_PS_SINGLE_RE = re.compile(f"[{_PS_SINGLE}]")
# What a backtick escape stands for inside a PowerShell double-quoted string.
_PS_ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "e": "\x1b", "f": "\f", "n": "\n", "r": "\r",
               "t": "\t", "v": "\v"}
# Characters with no meaning to the shell, read in one step rather than one at a time.
_PLAIN_RUN = {
    "bash": re.compile(r"[A-Za-z0-9_./:=,+%!~*?^\[\]-]+"),
    "powershell": re.compile(r"[A-Za-z0-9_./:=,+%!~*?^\[\]\\-]+"),
    "cmd": re.compile(r"[A-Za-z0-9_./:=,+%!~*?\[\]\\-]+"),
}
# What ends a run of plain text inside double quotes.
_DOUBLE_SPECIAL = {
    "bash": re.compile(r'[\\"$`]'),
    "powershell": re.compile(f'[`$"{_PS_DOUBLE[1:]}]'),
    "cmd": re.compile(r'"'),
}
# What ends a here-document's delimiter word.
_WORD_END = frozenset(" \t\n;&|()<>")
_ANSI_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r",
                "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}
_ANSI_HEX = {"x": re.compile(r"[0-9A-Fa-f]{1,2}"), "u": re.compile(r"[0-9A-Fa-f]{1,4}"),
             "U": re.compile(r"[0-9A-Fa-f]{1,8}")}
_ANSI_OCTAL = re.compile(r"[0-7]{1,3}")


class _Lexer:
    """Reads a command line into pipelines of commands, and each command into the words the
    shell would pass, the way the shell does.

    Quotes, escapes, line continuations, comments and here-documents are the shell's, so a
    separator inside quotes never splits a command and an apostrophe in a here-document is not a
    quote. Each command substitution's text is kept in ``subs``, to be read as commands of its own:
    only the outermost reading records them, the rest are re-read from their text. Anything that
    does not close (a quote, a substitution) raises ``_Unreadable``. One pass over the text, so a
    long command line costs time in proportion to its length.
    """

    def __init__(self, text: str, shell: str) -> None:
        self.s = text
        self.n = len(text)
        self.shell = shell
        self.esc = _ESCAPE[shell]
        self.subs: list[str] = []
        self.pipelines: list[list[_Stage]] = []

    def lex(self) -> _Lexer:
        self._commands(0, None, 0)
        return self

    def _commands(self, i: int, closer: str | None, nest: int) -> int:
        """Read commands from ``i`` to the ``)`` that closes a substitution (its index is
        returned), or to the end of the text at the top level, which alone records commands."""
        if nest > _MAX_NESTING:
            raise _Unreadable
        s, n, sh, esc = self.s, self.n, self.shell, self.esc
        plain_run = _PLAIN_RUN[sh]
        top = closer is None
        stage = _Stage()
        pipeline: list[_Stage] = []
        heredocs: list[tuple[str, bool, bool, _Stage]] = []
        word: list[str] = []
        in_word = False
        parens = 0
        last = ""

        def put(raw: str, value: str | None = None) -> None:
            """Add to the current word: ``value`` as the shell passes it, ``raw`` as written."""
            nonlocal last, in_word
            if raw:
                last = raw[-1]
            in_word = True
            if top:
                stage.text.append(raw)
                word.append(raw if value is None else value)

        def end_word() -> None:
            nonlocal in_word
            if in_word and top:
                stage.words.append("".join(word))
            word.clear()
            in_word = False

        def cut(piped: bool) -> None:
            nonlocal stage, pipeline, last
            end_word()
            if top:
                pipeline.append(stage)
                if not piped:
                    self.pipelines.append(pipeline)
                    pipeline = []
            stage = _Stage()
            last = ""

        while i < n:
            c = s[i]
            nx = s[i + 1] if i + 1 < n else ""
            if c == closer and parens == 0:
                return i
            plain = plain_run.match(s, i)
            if plain:
                put(plain.group())
                i = plain.end()
                continue
            if c == esc:
                if nx == "\n":
                    i += 2  # a line continuation: the next line goes on with this command
                else:
                    put(s[i:i + 2], nx)
                    i += 2
                continue
            if c == "\n":
                cut(False)
                i = self._heredoc_bodies(i + 1, heredocs, top)
                continue
            if c in " \t" or (sh == "powershell" and c.isspace()):
                end_word()
                if top:
                    stage.text.append(" ")
                i += 1
                continue
            if c == "#" and not in_word and sh != "cmd":
                end = s.find("\n", i)  # a comment, to the end of the line
                i = n if end < 0 else end
                continue
            if sh == "powershell" and c == "<" and nx == "#":
                end = s.find("#>", i + 2)
                if end < 0:
                    raise _Unreadable
                i = end + 2
                continue
            if sh == "bash" and c == "$" and nx in ("'", '"'):
                if nx == "'":
                    end, value = self._ansi_c(i + 2)
                    put(s[i:end], value)
                    i = end
                else:
                    i += 1  # `$"..."` is a translated string: it reads like a plain one
                continue
            if (sh == "bash" and c == "'") or (sh == "powershell" and c in _PS_SINGLE):
                end, value = self._single(i + 1)
                put(s[i:end], value)
                i = end
                continue
            if c == '"' or (sh == "powershell" and c in _PS_DOUBLE):
                end, value = self._double(i + 1, nest, top)
                put(s[i:end], value)
                i = end
                continue
            if sh == "powershell" and c == "@" and nx and nx in _PS_SINGLE + _PS_DOUBLE:
                here = self._here_string(i, nest, top)
                if here is not None:
                    end, value = here
                    put(s[i:end], value)
                    i = end
                    continue
            if sh != "cmd" and c == "$" and nx == "(":
                i = self._substitution(i + 2, nest, top)
                put(_SUB)
                continue
            if sh == "powershell" and c == "$" and nx == "{":
                end = s.find("}", i + 2)  # `${env:x}`, a variable with a braced name
                if end < 0:
                    raise _Unreadable
                put(s[i:end + 1])
                i = end + 1
                continue
            if sh == "bash":
                if c == "$" and nx == "{":
                    end = self._parameter(i + 2, nest + 1, top)
                    put(s[i:end])
                    i = end
                    continue
                if c == "`":
                    i = self._backtick(i + 1, top)
                    put(_SUB)
                    continue
                if c in "<>" and nx == "(":  # process substitution
                    i = self._substitution(i + 2, nest, top)
                    put(_SUB)
                    continue
                if c == "<" and nx == "<" and s[i + 2:i + 3] != "<":
                    end, delimiter, strip, expand = self._heredoc_operator(i + 2)
                    heredocs.append((delimiter, strip, expand, stage))
                    put(s[i:end], "<<" + delimiter)
                    i = end
                    continue
                if c == "(" and nx == "(" and not in_word:
                    end = self._arithmetic(i + 2, nest + 1, top)
                    if end is not None:  # `(( x << 2 ))`: arithmetic, not a here-document
                        put("((...))")
                        i = end
                        continue
            # Operators that end a command.
            if c == ";":
                cut(False)
                i += 1
                while i < n and s[i] in ";&":  # `;;`, `;&` and `;;&` end a case branch
                    i += 1
                continue
            if c == "&":
                if nx == "&":
                    cut(False)
                    i += 2
                elif last in ("<", ">") or (sh == "bash" and nx == ">"):
                    put(c)  # `2>&1`, `&> log`: a redirection
                    i += 1
                else:
                    cut(False)
                    i += 1
                continue
            if c == "|":
                if nx == "|":
                    cut(False)
                    i += 2
                elif last == ">":
                    put(c)  # `>| log`
                    i += 1
                else:
                    cut(True)
                    i += 2 if (sh == "bash" and nx == "&") else 1
                continue
            if c in "()":
                if top:
                    cut(False)
                else:
                    parens += 1 if c == "(" else -1
                i += 1
                continue
            if c in "{}" and not in_word and self._group(i):
                if top:
                    cut(False)
                i += 1
                continue
            put(c)
            i += 1
        if not top:
            raise _Unreadable  # a substitution that never closes
        cut(False)
        return n

    def _group(self, i: int) -> bool:
        """A brace that opens or closes a group of commands (`{ npm i x; }`, a PowerShell script
        block), as opposed to one inside a word (`{a,b}`, `find -exec ... {}`)."""
        if self.shell == "powershell":
            return True
        if self.shell != "bash":
            return False
        nx = self.s[i + 1:i + 2]
        if self.s[i] == "{":
            return nx in ("", " ", "\t", "\n")
        return nx in ("", " ", "\t", "\n", ";", "&", "|", ")")

    def _single(self, i: int) -> tuple[int, str]:
        """A single-quoted string from just inside its quote: where it ends and what it holds.
        No escapes, except PowerShell's doubled quote."""
        s = self.s
        if self.shell != "powershell":
            end = s.find("'", i)
            if end < 0:
                raise _Unreadable
            return end + 1, s[i:end]
        parts = []
        while True:
            found = _PS_SINGLE_RE.search(s, i)
            if found is None:
                raise _Unreadable
            end = found.start()
            parts.append(s[i:end])
            if s[end + 1:end + 2] and s[end + 1] in _PS_SINGLE:
                parts.append("'")  # '' stands for one quote
                i = end + 2
                continue
            return end + 1, "".join(parts)

    def _double(self, i: int, nest: int, record: bool) -> tuple[int, str]:
        """A double-quoted string from just inside its quote: where it ends and what it holds,
        each substitution in it standing as ``$(...)``."""
        if nest > _MAX_NESTING:
            raise _Unreadable
        s, n, sh = self.s, self.n, self.shell
        special = _DOUBLE_SPECIAL[sh]
        out: list[str] = []
        while i < n:
            ahead = special.search(s, i)
            if ahead is None:
                break
            if ahead.start() > i:
                out.append(s[i:ahead.start()])
                i = ahead.start()
            c = s[i]
            if sh == "bash" and c == "\\":
                nx = s[i + 1:i + 2]
                if nx != "\n":  # a backslash-newline joins the lines
                    out.append(nx if nx in ('"', "\\", "$", "`") else s[i:i + 2])
                i += 2
                continue
            if sh == "powershell" and c == "`":
                nx = s[i + 1:i + 2]
                out.append(_PS_ESCAPES.get(nx, nx))
                i += 2
                continue
            if c == '"' or (sh == "powershell" and c in _PS_DOUBLE):
                if sh == "powershell" and s[i + 1:i + 2] and s[i + 1] in _PS_DOUBLE:
                    out.append('"')  # "" stands for one quote
                    i += 2
                    continue
                return i + 1, "".join(out)
            if sh != "cmd" and c == "$" and s[i + 1:i + 2] == "(":
                i = self._substitution(i + 2, nest + 1, record)
                out.append(_SUB)
                continue
            if sh == "bash" and c == "$" and s[i + 1:i + 2] == "{":
                end = self._parameter(i + 2, nest + 1, record)
                out.append(s[i:end])
                i = end
                continue
            if sh == "bash" and c == "`":
                i = self._backtick(i + 1, record)
                out.append(_SUB)
                continue
            out.append(c)
            i += 1
        raise _Unreadable

    def _ansi_c(self, i: int) -> tuple[int, str]:
        """Bash's ``$'...'`` from just inside its quote: where it ends and what it holds, decoded
        the way the shell decodes it."""
        s, n = self.s, self.n
        out = []
        while i < n:
            c = s[i]
            if c == "'":
                return i + 1, "".join(out)
            if c == "\\" and i + 1 < n:
                value, i = _ansi_escape(s, i + 1)
                out.append(value)
                continue
            out.append(c)
            i += 1
        raise _Unreadable

    def _substitution(self, i: int, nest: int, record: bool) -> int:
        """``$(...)`` (or ``<(...)``) from just inside its parenthesis: the index past its end.
        ``$((...))`` is arithmetic, unless it does not close like arithmetic."""
        s = self.s
        if s[i:i + 1] == "(":
            end = self._arithmetic(i + 1, nest + 1, False)
            if end is not None:
                if record:
                    self.subs.append(s[i + 1:end - 2])
                return end
        end = self._commands(i, ")", nest + 1)
        if record:
            self.subs.append(s[i:end])
        return end + 1

    def _backtick(self, i: int, record: bool) -> int:
        """A backquoted substitution from just inside its quote: the index past its end."""
        s, n = self.s, self.n
        out = []
        while i < n:
            c = s[i]
            if c == "\\" and s[i + 1:i + 2] in ("`", "\\", "$"):
                out.append(s[i + 1])
                i += 2
                continue
            if c == "`":
                if record:
                    self.subs.append("".join(out))
                return i + 1
            out.append(c)
            i += 1
        raise _Unreadable

    def _parameter(self, i: int, nest: int, record: bool) -> int:
        """``${...}`` from just inside its brace: the index past its end."""
        if nest > _MAX_NESTING:
            raise _Unreadable
        s, n = self.s, self.n
        depth = 0
        while i < n:
            c = s[i]
            if c == "\\":
                i += 2
            elif c == "'":
                end = s.find("'", i + 1)
                if end < 0:
                    raise _Unreadable
                i = end + 1
            elif c == '"':
                i = self._double(i + 1, nest + 1, record)[0]
            elif c == "$" and s[i + 1:i + 2] == "(":
                i = self._substitution(i + 2, nest + 1, record)
            elif c == "$" and s[i + 1:i + 2] == "{":
                i = self._parameter(i + 2, nest + 1, record)
            elif c == "`":
                i = self._backtick(i + 1, record)
            else:
                if c == "{":
                    depth += 1
                elif c == "}":
                    if depth == 0:
                        return i + 1
                    depth -= 1
                i += 1
        raise _Unreadable

    def _arithmetic(self, i: int, nest: int, record: bool) -> int | None:
        """``((...))`` from just inside it: the index past ``))``, or None when it does not close
        that way (then it was a subshell after all)."""
        if nest > _MAX_NESTING:
            raise _Unreadable
        s, n = self.s, self.n
        depth = 0
        while i < n:
            c = s[i]
            if c == "\\":
                i += 2
            elif c in "'\"":
                end = s.find(c, i + 1)
                if end < 0:
                    return None
                i = end + 1
            elif c == "$" and s[i + 1:i + 2] == "(":
                i = self._substitution(i + 2, nest + 1, record)
            elif c == "`":
                i = self._backtick(i + 1, record)
            else:
                if c == "(":
                    depth += 1
                elif c == ")":
                    if depth == 0:
                        return i + 2 if s[i + 1:i + 2] == ")" else None
                    depth -= 1
                i += 1
        return None

    def _heredoc_operator(self, i: int) -> tuple[int, str, bool, bool]:
        """``<<[-]WORD`` from just past ``<<``: where it ends, the delimiter, whether tabs are
        stripped, and whether the body is expanded (an unquoted delimiter)."""
        s, n = self.s, self.n
        strip = s[i:i + 1] == "-"
        if strip:
            i += 1
        while i < n and s[i] in " \t":
            i += 1
        word: list[str] = []
        quoted = False
        while i < n and s[i] not in _WORD_END:
            c = s[i]
            if c in "'\"":
                end = s.find(c, i + 1)
                if end < 0:
                    raise _Unreadable
                word.append(s[i + 1:end])
                quoted, i = True, end + 1
            elif c == "\\" and i + 1 < n:
                word.append(s[i + 1])
                quoted, i = True, i + 2
            else:
                word.append(c)
                i += 1
        if not word and not quoted:
            raise _Unreadable
        return i, "".join(word), strip, not quoted

    def _heredoc_bodies(self, i: int, heredocs: list[tuple[str, bool, bool, _Stage]],
                        record: bool) -> int:
        """Read each pending here-document body, from the line after its operator to its
        delimiter. With an unquoted delimiter the shell expands the body as it reads it, which
        runs the substitutions in it."""
        s, n = self.s, self.n
        for delimiter, strip, expand, stage in heredocs:
            lines = []
            while i < n:
                end = s.find("\n", i)
                end = n if end < 0 else end
                line = s[i:end].lstrip("\t") if strip else s[i:end]
                i = end + 1
                if line == delimiter:
                    break
                lines.append(line)
            body = "\n".join(lines)
            if expand and record:
                self._expansions(body)
            stage.bodies.append(body)
        heredocs.clear()
        return min(i, n)

    def _expansions(self, body: str) -> None:
        """Record the command substitutions an expanded here-document body runs."""
        inner = _Lexer(body, "bash")
        inner.subs = self.subs
        i, n = 0, len(body)
        while i < n:
            c = body[i]
            if c == "\\":
                i += 2
            elif c == "$" and body[i + 1:i + 2] == "(":
                i = inner._substitution(i + 2, 1, True)
            elif c == "$" and body[i + 1:i + 2] == "{":
                i = inner._parameter(i + 2, 1, True)
            elif c == "`":
                i = inner._backtick(i + 1, True)
            else:
                i += 1

    def _here_string(self, i: int, nest: int, record: bool) -> tuple[int, str] | None:
        """A PowerShell here-string (``@'`` or ``@"`` and a newline, to a line that starts with
        the closing quote and ``@``): where it ends and what it holds."""
        s, n = self.s, self.n
        double = s[i + 1] in _PS_DOUBLE
        j = i + 2
        while j < n and s[j] in " \t":
            j += 1
        if j >= n or s[j] != "\n":
            return None
        start = line = j + 1
        closers = _PS_DOUBLE if double else _PS_SINGLE
        while line < n:
            if s[line] in closers and s[line + 1:line + 2] == "@":
                body = s[start:max(start, line - 1)]
                if double:
                    k = start
                    while k < line:
                        if s[k] == "`":
                            k += 2
                        elif s[k] == "$" and s[k + 1:k + 2] == "(":
                            k = self._substitution(k + 2, nest + 1, record)
                        else:
                            k += 1
                return line + 2, body
            end = s.find("\n", line)
            if end < 0:
                break
            line = end + 1
        raise _Unreadable


def _ansi_escape(s: str, i: int) -> tuple[str, int]:
    """One ``$'...'`` escape from just past its backslash: the text and where it ends."""
    c = s[i]
    if c in _ANSI_SIMPLE:
        return _ANSI_SIMPLE[c], i + 1
    if c in _ANSI_HEX:
        digits = _ANSI_HEX[c].match(s, i + 1)
        if digits:
            return chr(min(int(digits.group(), 16), 0x10FFFF)), digits.end()
        return "\\" + c, i + 1
    if c in "01234567":
        digits = _ANSI_OCTAL.match(s, i)
        return chr(int(digits.group(), 8) & 0xFF), digits.end()
    if c == "c" and i + 1 < len(s):
        return chr(ord(s[i + 1]) & 0x1F), i + 2
    return "\\" + c, i + 1


# A redirection: `> log`, `2>&1`, `&> log`, `<<< text`, `<<EOF`. The target is in the same word or
# the next one.
_REDIRECT = re.compile(r"(?:[0-9]+|&|\*)?(<<<|<<-|<<|<>|<&|<|>>|>&|>\||>)")


def _redirects(words: list[str]) -> tuple[list[str], list[str]]:
    """The command's words without its redirections, and what here-strings feed it on stdin."""
    kept: list[str] = []
    fed: list[str] = []
    i = 0
    while i < len(words):
        found = _REDIRECT.match(words[i])
        if found is None:
            kept.append(words[i])
            i += 1
            continue
        target = words[i][found.end():]
        i += 1
        if not target and i < len(words):
            target = words[i]
            i += 1
        if found.group(1) == "<<<":
            fed.append(target)
    return kept, fed


def _output_of(words: list[str], feed: list[tuple[str, bool]], line: str,
               shell: str) -> tuple[str, bool]:
    """What a command writes into the next one in its pipeline, and whether it could be read:
    ``echo 'npm i x' | sh`` runs ``npm i x``. Anything else counts as its own text, unread."""
    words = _unwrap(words)
    head, args = (_base(words[0]), words[1:]) if words else ("", [])
    if head in ("echo", "write-output", "write-host", "write"):
        if shell == "bash":
            while args and args[0] in ("-n", "-E"):
                args = args[1:]
            if args and args[0].startswith("-e"):
                return line, False  # escapes the shell decodes: not read here
        return " ".join(args), True
    if head == "printf" and len(args) == 1 and "%" not in args[0] and "\\" not in args[0]:
        return args[0], True
    if head == "cat" and not args and feed:
        return "\n".join(text for text, _ in feed), all(readable for _, readable in feed)
    if shell == "powershell" and len(words) == 1:
        return words[0], True  # a bare string is written down the pipeline
    return line, False


@functools.lru_cache(maxsize=1024)
def _base(token: str) -> str:
    """``/usr/bin/npm`` / ``C:\\nodejs\\npm.cmd`` -> ``npm``."""
    name = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    stem, dot, ext = name.rpartition(".")
    return stem if dot and ext in ("exe", "cmd", "bat", "ps1") else name


def _unwrap(tokens: list[str]) -> list[str]:
    """Drop ``VAR=x``, shell keywords (``then``, ``do``, ``!``), ``sudo -u root``, ``env -i``,
    ``timeout 60``... in front of the command."""
    while tokens:
        if _ENV_ASSIGN.match(tokens[0]) or tokens[0].lower() in _KEYWORDS:
            tokens = tokens[1:]
            continue
        head = _base(tokens[0])
        if head not in _WRAPPERS:
            return tokens
        value_flags = _WRAPPERS[head]
        i = 1
        # `env` sets any NAME=VALUE before the command, even one no shell would accept as a
        # variable name (`npm_config_@scope:registry=...`).
        while i < len(tokens) and (tokens[i].startswith("-") or _ENV_ASSIGN.match(tokens[i])
                                   or (head == "env" and "=" in tokens[i])):
            i += 2 if tokens[i] in value_flags else 1
        if head == "timeout" and i < len(tokens):
            i += 1  # the duration
        tokens = tokens[i:]
    return tokens


def _installs_in(tokens: list[str], shell: str, depth: int, level: _Level,
                 feed: list[tuple[str, bool]] | None = None) -> list[Install]:
    """What one command installs. ``feed`` is what it reads on stdin: a here-document, a
    here-string, or the output of the command piped into it (with whether it could be read)."""
    tokens = _unwrap(tokens)
    if not tokens:
        return []
    if depth > _MAX_DEPTH:
        return _net(" ".join(tokens))
    head, rest = _base(tokens[0]), tokens[1:]
    if shell == "powershell" and head == "." and rest:  # dot-sourcing runs the command too
        head, rest = _base(rest[0]), rest[1:]
    if shell == "cmd" and (head == "rem" or tokens[0].startswith("::")):
        return []  # a cmd comment

    if head in _SHELLS or head in ("cmd", "powershell", "pwsh"):
        return _shell(head, rest, shell, depth, level, feed or [])
    if shell == "powershell" and head in _PS_EVAL:
        args = [a for a in rest if a.lower() != "-command"]
        return _run(" ".join(args), "powershell", depth, level) if args else []
    if shell == "powershell" and head in _PS_START:
        started = _start_process(rest)
        if started is None:
            return _net(" ".join(rest))
        return _installs_in(started, shell, depth + 1, level) if started else []
    if head == "claude" and rest[:2] == ["mcp", "add"]:
        return _launched(rest[2:], shell, depth, level)
    if head == "claude" and rest[:2] == ["mcp", "add-json"]:
        return _add_json(rest[2:], shell, depth, level)
    if head in _NPM_RUNNERS:
        return _npx(rest)
    if head in ("npm", "pnpm", "yarn", "bun"):
        return _node_manager(head, rest)
    if _PIP_HEAD.fullmatch(head):
        sub, args = _subcommand(rest, _PIP_VALUE_FLAGS)
        return _pip_install(args) if sub == "install" else []
    if _PYTHON_HEAD.fullmatch(head):
        return _python_module(rest)
    if head == "uv":
        return _uv(rest)
    if head == "uvx":
        return _uvx(rest)
    if head == "pipx":
        return _pipx(rest)
    return []


def _shell(head: str, rest: list[str], shell: str, depth: int, level: _Level,
           feed: list[tuple[str, bool]]) -> list[Install]:
    """A shell runs its ``-c`` text, else the script it reads on stdin."""
    inner = _inner_command(head, rest, shell)
    if inner is not None:
        return _run(inner[0], inner[1], depth, level)
    if not _reads_stdin(head, rest):
        return []
    flavor = {"cmd": "cmd", "powershell": "powershell", "pwsh": "powershell"}.get(head, "bash")
    found: dict[Install, None] = {}
    for text, readable in feed:
        found.update(dict.fromkeys(_run(text, flavor, depth, level) if readable else _net(text)))
    return list(found)


def _reads_stdin(head: str, rest: list[str]) -> bool:
    """Whether a shell started this way runs the script on its stdin: no script file named, or
    ``-``, or ``-s``."""
    if head == "cmd":
        return not any(a.lower() in ("/c", "/k") for a in rest)
    if head in ("powershell", "pwsh"):
        return "-" in rest
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg in ("-", "-s") or (arg.startswith("-") and not arg.startswith("--")
                                  and "s" in arg[1:]):
            return True
        if arg in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file"):
            i += 2
        elif arg.startswith(("-", "+")):
            i += 1
        else:
            return False  # a script file: it runs that, not its stdin
    return True


def _launched(args: list[str], shell: str, depth: int, level: _Level) -> list[Install]:
    """Everything a command that starts another program could run, read from every place that
    program could start.

    Where it starts depends on options the hook would have to parse exactly as the tool does
    (``claude mcp add``'s ``-e``/``-H`` take several values; the name may come after ``--``), and a
    word misread there is a package never checked. So every place a launcher could start (``npx``,
    ``uvx``, ``npm``, ``pip``, a shell or a wrapper) is read as a command, and everything any of
    them would install is checked. One quoted word holding a whole command line (``"npx evil"``)
    is read as one: a program started through a shell runs it as such. A remote MCP server (a URL)
    installs nothing.
    """
    found: dict[Install, None] = {}
    tried = 0
    for i, word in enumerate(args):
        if _could_launch(word):
            items = _installs_in(args[i:], shell, depth + 1, level)
        elif any(c.isspace() for c in word):
            items = _run(word, shell, depth, level)
        else:
            continue
        found.update(dict.fromkeys(items))
        tried += 1
        if tried == _MAX_LAUNCHES:
            found.update(dict.fromkeys(_net(" ".join(args[i + 1:]))))
            break
    return list(found)


def _could_launch(word: str) -> bool:
    """True for a word that can start a command the hook reads (a package runner or manager, a
    Python, a shell or a wrapper)."""
    head = _base(word)
    return (
        head in _NPM_RUNNERS or head in ("npm", "pnpm", "yarn", "bun", "uv", "uvx", "pipx", "cmd",
                                         "powershell", "pwsh")
        or head in _SHELLS or head in _WRAPPERS
        or bool(_PIP_HEAD.fullmatch(head) or _PYTHON_HEAD.fullmatch(head))
    )


def _add_json(args: list[str], shell: str, depth: int, level: _Level) -> list[Install]:
    """``claude mcp add-json <name> '{"command": "npx", "args": ["-y", "pkg"]}'`` starts the server
    with that command.

    Every argument that reads as a JSON object is taken as a config, rather than trusting a
    reading of the options in front of it. A config that cannot be read is asked about.
    """
    found: dict[Install, None] = {}
    configs = 0
    for word in args:
        if not word.lstrip().startswith("{"):
            continue
        try:
            config = json.loads(word)
        except ValueError:
            continue
        if not isinstance(config, dict):
            continue
        configs += 1
        command, extra = config.get("command"), config.get("args")
        if not isinstance(command, str):
            continue  # a remote server: nothing is installed
        words = [command, *(str(a) for a in extra if isinstance(a, (str, int, float)))] if (
            isinstance(extra, list)) else [command]
        found.update(dict.fromkeys(_launched(["<name>", *words], shell, depth, level)))
    if not configs:
        return [Install(None, "a `claude mcp add-json` server config SkillTotal could not read")]
    return list(found)


def _inner_command(head: str, rest: list[str], shell: str) -> tuple[str, str] | None:
    """The command string another shell would run, and how it is quoted: ``bash -lc '...'``,
    ``cmd /c ...``, ``pwsh -c ...``, ``powershell -EncodedCommand ...``."""
    if head in _SHELLS:
        for i, arg in enumerate(rest):
            if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
                return (rest[i + 1], "bash") if i + 1 < len(rest) else None
        return None
    if head == "cmd":
        for i, arg in enumerate(rest):
            if arg.lower() in ("/c", "/k"):
                return " ".join(rest[i + 1:]), "cmd"
        return None
    if head in ("powershell", "pwsh"):
        for i, arg in enumerate(rest):
            flag = arg.lower().lstrip("-/")
            if flag in ("command", "c"):
                text = " ".join(rest[i + 1:])
                return (text, "powershell") if text != "-" else None  # `-Command -`: stdin
            if flag in ("encodedcommand", "enc", "ec", "e") and i + 1 < len(rest):
                decoded = _decode_ps(rest[i + 1])
                return (decoded, "powershell") if decoded else None
        return None
    return None


def _decode_ps(value: str) -> str | None:
    """``-EncodedCommand`` is base64 of the UTF-16LE command line."""
    try:
        return base64.b64decode(value, validate=True).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


# Start-Process parameters that take a value (only the program and its arguments matter here).
_START_PARAMS = {
    "file": ("filepath", "path", "pspath"),
    "args": ("argumentlist", "args"),
    "other": ("workingdirectory", "verb", "windowstyle", "redirectstandardoutput",
              "redirectstandarderror", "redirectstandardinput", "credential", "environment"),
}


def _start_process(rest: list[str]) -> list[str] | None:
    """``Start-Process npm -ArgumentList 'install','x'`` -> ``npm install x``.

    PowerShell accepts any unambiguous prefix of a parameter name, so ``-Arg`` and ``-File`` count.
    """
    named: dict[str, str] = {}
    positional: list[str] = []
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg.startswith("-") and len(arg) > 1:
            name = arg[1:].lower()
            key = next((k for k, names in _START_PARAMS.items()
                        if any(n.startswith(name) for n in names)), None)
            if key and i + 1 < len(rest):
                named.setdefault(key, rest[i + 1])
                i += 2
            else:
                i += 1  # a switch such as -Wait or -NoNewWindow
            continue
        positional.append(arg)
        i += 1
    program = named.get("file") or (positional.pop(0) if positional else None)
    arguments = named.get("args") or (positional[0] if positional else "")
    if not program:
        return []
    words = [_words(part, "powershell") for part in arguments.split(",")]
    if any(w is None for w in words):
        return None
    return [program, *(w for part in words for w in part)]


def _subcommand(args: list[str], value_flags: set[str]) -> tuple[str | None, list[str]]:
    """Skip global options (and their values) to the subcommand: ``npm --silent install x``."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            i += 1
            continue
        if arg.startswith("-"):
            i += 2 if (arg in value_flags and "=" not in arg) else 1
            continue
        return arg.lower(), args[i + 1:]
    return None, []


def _node_manager(head: str, rest: list[str]) -> list[Install]:
    sub, args = _subcommand(rest, _NPM_VALUE_FLAGS)
    if head == "yarn" and sub == "global":
        sub, args = _subcommand(args, _NPM_VALUE_FLAGS)
    if sub in ("exec", "x", "dlx") and not (head == "pnpm" and sub == "exec"):
        return _npx(args)
    if sub in _SCAFFOLDERS[head]:
        return _scaffold(args, _custom_source(rest, _NPM_SOURCE_FLAGS))
    if head == "yarn" and sub != "add":
        return []  # `yarn install` installs the lockfile only
    if sub in _NPM_INSTALL or (head == "bun" and sub == "a"):
        return _npm_packages(args, _custom_source(rest, _NPM_SOURCE_FLAGS))
    return []


# Subcommands that run an initializer package from the registry (`npm create vite`). `pnpm init`,
# `yarn init` and `bun init` only write a package.json.
_SCAFFOLDERS = {"npm": {"create", "init", "innit"}, "yarn": {"create"}, "pnpm": {"create"},
                "bun": {"create", "c"}}
# `npm init` options that take a value, so the value is not taken for the initializer.
_INIT_VALUE_FLAGS = _NPM_VALUE_FLAGS | {
    "--scope", "--init-author-name", "--init-author-email", "--init-author-url",
    "--init-license", "--init-module", "--init-version"}


def _scaffold(args: list[str], registry: str | None) -> list[Install]:
    """``npm init x`` / ``npm create x`` / ``yarn create x`` fetch and run the initializer package
    ``create-x``; without one, ``npm init`` writes a package.json and installs nothing."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("-"):
            i += 2 if (arg in _INIT_VALUE_FLAGS and "=" not in arg) else 1
            continue
        return _npm_spec(_initializer_package(arg), registry)
    return []


def _initializer_package(spec: str) -> str:
    """npm's own mapping, version or tag kept: ``x`` -> ``create-x``, ``@scope`` ->
    ``@scope/create``, ``@scope/x`` -> ``@scope/create-x``, ``owner/repo`` (GitHub) ->
    ``owner/create-repo``. Anything else (a path, a URL) is left for ``_npm_spec`` to judge."""
    if spec.startswith("@"):
        scope, slash, rest = spec.partition("/")
        if not slash:
            scope, at, version = spec[1:].partition("@")
            return f"@{scope}/create{at}{version}"
        name, at, version = rest.partition("@")
        return f"{scope}/create-{name}{at}{version}"
    if "://" in spec or spec.startswith((".", "~", "file:", "git+", "git:")):
        return spec
    gh = _GH_SHORTHAND.match(spec)
    if gh:
        return f"{gh.group(1)}/create-{gh.group(2)}{gh.group('tail') or ''}"
    name, at, version = spec.partition("@")
    return f"create-{name}{at}{version}"


def _npx(args: list[str]) -> list[Install]:
    """``npx [-y] [-p pkg] pkg args``: the explicit ``-p`` package, else the first positional."""
    registry = _custom_source(args, _NPM_SOURCE_FLAGS)
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-p", "--package") and i + 1 < len(args):
            return _npm_spec(args[i + 1], registry)
        if arg.startswith("--package="):
            return _npm_spec(arg.split("=", 1)[1], registry)
        if arg.startswith("-"):
            i += 2 if (arg in _NPM_VALUE_FLAGS and "=" not in arg) else 1
            continue
        return _npm_spec(arg, registry)
    return []


def _npm_packages(args: list[str], registry: str | None) -> list[Install]:
    """Every package named after the install subcommand, wherever the flags sit."""
    out: list[Install] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg.startswith("-"):
            skip = arg in _NPM_VALUE_FLAGS and "=" not in arg
            continue
        out.extend(_npm_spec(arg, registry))
    return out


def _computed(spec: str) -> list[Install]:
    """A package named by a variable, a substitution or a brace expansion: the shell decides what
    it is when the command runs, so the hook cannot."""
    return [Install(None, f"{spec} (a name the shell fills in when the command runs)")]


def _npm_spec(spec: str, registry: str | None) -> list[Install]:
    """A registry name, a GitHub source, an unscannable remote, or a local path (ignored)."""
    if _COMPUTED.search(spec):
        return _computed(spec)
    if spec.startswith((".", "/", "~", "file:", "link:", "workspace:")) or _DRIVE.match(spec):
        return []  # the person's own code on disk
    alias = _NPM_ALIAS.match(spec)
    if alias:
        spec = alias.group(1)  # what npm fetches; the alias is only the folder it lands in
    gh = _github(spec)
    if gh:
        return [gh]
    if "://" in spec or spec.startswith(("git+", "git:", *_NPM_OTHER_HOSTS)):
        return [Install(None, f"{spec} (a remote archive or repository)")]
    versioned = spec.count("@") > (1 if spec.startswith("@") else 0)
    name, version = spec.rsplit("@", 1) if versioned else (spec, "")
    if not _NPM_NAME.match(name):
        return []
    if registry:
        return [Install(None, f"{name} from {registry}")]
    # The version the command asks for is the one to check: `npx x@0.1.2` must not be judged by
    # the latest release. A range (`^1.2`) is resolved by npm, not here, so it checks latest.
    return [Install(f"npm:{name}@{version}" if _NPM_EXACT.fullmatch(version) else f"npm:{name}")]


def _github(spec: str, *, pip: bool = False) -> Install | None:
    """``github:o/r#v1``, ``o/r``, ``git+https://github.com/o/r.git@main`` -> the repository at
    the ref the installer checks out, or None when the spec is not a GitHub source.

    The ref decides what gets installed, so dropping it would scan the default branch while the
    installer fetched a branch the author kept for the purpose. The two installers spell it
    differently: pip takes ``@ref`` and keeps ``#egg=...&subdirectory=...`` for metadata, npm takes
    everything after ``#`` as the ref. A ref the scan cannot reproduce exactly (a branch with a
    slash, an npm ``#semver:`` range) is not guessed at: the person is asked.
    """
    m = _GH_URL.match(spec)
    if m:
        tail = m.group("tail") or ""
        if tail.startswith("@"):  # `@ref`, then (pip) an optional `#egg=...` fragment
            ref = tail[1:].split("#", 1)[0] if pip else tail[1:]
        elif pip:
            # pip never takes a ref from the fragment: it installs the default branch. Anything
            # there but its own metadata keys is something the scan cannot account for.
            if tail and not _PIP_FRAGMENT.fullmatch(tail[1:]):
                return Install(None, f"{spec} (a URL fragment the scan cannot interpret)")
            ref = ""
        else:
            ref = tail[1:]
    elif spec.startswith(("@", "git+", "git:")) or "://" in spec:
        return None  # a scoped npm name, or a non-GitHub remote
    else:
        m = _GH_SHORTHAND.match(spec)
        if not m:
            return None
        ref = (m.group("tail") or "")[1:]
    url = f"https://github.com/{m.group(1)}/{m.group(2)}"
    if not ref:
        return Install(url)
    if _PLAIN_REF.fullmatch(ref):
        return Install(f"{url}/tree/{ref}")
    return Install(None, f"{spec} (a git ref the scan cannot reproduce exactly)")


def _flag_value(args: list[str], flags: set[str]) -> str | None:
    for i, arg in enumerate(args):
        if arg in flags and i + 1 < len(args):
            return args[i + 1]
        key, _, value = arg.partition("=")
        if value and key in flags:
            return value
    return None


# The public registries the scan itself reads, named explicitly (`-i https://pypi.org/simple`).
_PUBLIC_SOURCES = frozenset({
    "https://registry.npmjs.org", "https://registry.yarnpkg.com",
    "https://pypi.org/simple", "https://pypi.python.org/simple",
})


def _custom_source(args: list[str], flags: set[str]) -> str | None:
    """The first package source a command names other than the public registry, or None.

    Every source flag counts: `-i https://pypi.org/simple --extra-index-url https://x` installs
    from both, and the extra index can serve the higher version.
    """
    for i, arg in enumerate(args):
        key, _, value = arg.partition("=")
        if arg in flags and i + 1 < len(args):
            value = args[i + 1]
        elif not (value and key in flags):
            continue
        if value.rstrip("/").lower() not in _PUBLIC_SOURCES:
            return value
    return None


def _pip_install(args: list[str]) -> list[Install]:
    index = _custom_source(args, _PIP_SOURCE_FLAGS)
    out: list[Install] = []
    skip = False
    for i, arg in enumerate(args):
        if skip:
            skip = False
            continue
        # `-e .` is the person's own checkout, but `-e git+https://...` fetches a repository.
        editable = None
        if arg in ("-e", "--editable"):
            editable, skip = (args[i + 1] if i + 1 < len(args) else ""), True
        elif arg.startswith("--editable="):
            editable = arg.split("=", 1)[1]
        elif arg.startswith("-e") and not arg.startswith("--"):
            editable = arg[2:]
        if editable is not None:
            out.extend(_py_spec(editable, index))
            continue
        if arg.startswith("-"):
            skip = (arg in _PIP_VALUE_FLAGS or arg in _UV_VALUE_FLAGS) and "=" not in arg
            continue
        out.extend(_py_spec(arg, index))
    return out


def _py_spec(spec: str, index: str | None) -> list[Install]:
    """``fastapi[standard]>=0.110`` -> pypi:fastapi; a GitHub VCS spec is scanned from GitHub."""
    if _COMPUTED.search(spec):
        return _computed(spec)
    if not spec or spec.startswith((".", "/", "~")) or _DRIVE.match(spec):
        return []
    gh = _github(spec, pip=True) if ("://" in spec or spec.startswith("git+")) else None
    if gh:
        return [gh]
    if "://" in spec or spec.startswith("git+"):
        return [Install(None, f"{spec} (a remote archive or repository)")]
    if spec.endswith((".whl", ".tar.gz", ".zip")) or "/" in spec or "\\" in spec:
        return []  # a local file
    m = _PY_NAME.match(spec)
    if not m:
        return []
    if index:
        return [Install(None, f"{m.group(0)} from {index}")]
    # `requests==2.31.0` checks 2.31.0; a range or wildcard is resolved by pip, so it checks latest.
    pin = _PY_EXACT.match(re.sub(r"^\[[^\]]*\]", "", spec[m.end():]))
    return [Install(f"pypi:{m.group(0)}=={pin.group(1)}" if pin else f"pypi:{m.group(0)}")]


def _python_module(rest: list[str]) -> list[Install]:
    """``python [-I] [-X opt] -m pip install x`` (and ``-m pipx`` / ``-m uv``)."""
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg == "-m" and i + 1 < len(rest):
            module, args = _base(rest[i + 1]), rest[i + 2:]
            if re.fullmatch(r"pip\d*", module):
                sub, sub_args = _subcommand(args, _PIP_VALUE_FLAGS)
                return _pip_install(sub_args) if sub == "install" else []
            if module == "pipx":
                return _pipx(args)
            if module == "uv":
                return _uv(args)
            return []
        if arg.startswith("-"):
            i += 2 if arg in _PY_VALUE_FLAGS else 1
            continue
        return []  # `python script.py`
    return []


def _uv(rest: list[str]) -> list[Install]:
    sub, args = _subcommand(rest, _UV_VALUE_FLAGS)
    if sub == "add":
        return _pip_install(args)
    if sub == "pip":
        sub2, args2 = _subcommand(args, _PIP_VALUE_FLAGS | _UV_VALUE_FLAGS)
        return _pip_install(args2) if sub2 == "install" else []
    if sub == "tool":
        sub2, args2 = _subcommand(args, _UV_VALUE_FLAGS)
        if sub2 == "install":
            return _first_py(args2) + _with_values(args2)
        if sub2 == "run":
            return _uvx(args2)
        return []
    if sub == "run":
        return _with_values(args)  # `uv run --with pkg script.py` installs pkg
    return []


def _uvx(args: list[str]) -> list[Install]:
    """``uvx [--from pkg] [--with dep] tool args``: ``--from`` names the package, else the tool."""
    found = _with_values(args)
    source = _flag_value(args, {"--from"})
    if source:
        return _py_spec(source, _custom_source(args, _PIP_SOURCE_FLAGS)) + found
    return _first_py(args) + found


def _with_values(args: list[str]) -> list[Install]:
    index = _custom_source(args, _PIP_SOURCE_FLAGS)
    out: list[Install] = []
    for i, arg in enumerate(args):
        value = None
        if arg == "--with" and i + 1 < len(args):
            value = args[i + 1]
        elif arg.startswith("--with="):
            value = arg.split("=", 1)[1]
        for spec in (value or "").split(","):
            out.extend(_py_spec(spec.strip(), index))
    return out


def _first_py(args: list[str]) -> list[Install]:
    """The first positional (the tool or package), skipping flags and their values."""
    index = _custom_source(args, _PIP_SOURCE_FLAGS)
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("-"):
            i += 2 if (arg in _UV_VALUE_FLAGS and "=" not in arg) else 1
            continue
        return _py_spec(arg, index)
    return []


def _pipx(rest: list[str]) -> list[Install]:
    sub, args = _subcommand(rest, _UV_VALUE_FLAGS | _PIP_VALUE_FLAGS)
    if sub in ("install", "run"):
        return _first_py(args)
    if sub == "inject":
        positional = [a for a in args if not a.startswith("-")]
        index = _custom_source(args, _PIP_SOURCE_FLAGS)
        return [x for spec in positional[1:] for x in _py_spec(spec, index)]
    return []


Scan = Callable[[str, float], dict[str, Any]]
# Claude Code's command tools, and how each one quotes a command line.
_TOOL_SHELLS = {"Bash": "bash", "PowerShell": "powershell"}


def hook_response(
    event: dict[str, Any], scan: Scan, budget_s: float = DEFAULT_BUDGET_S
) -> dict[str, Any] | None:
    """Claude Code's answer for one PreToolUse event, or None to stay silent.

    ``scan(source, timeout)`` returns a serialized report (``Report.to_dict()``) for a source such
    as ``npm:name``, or raises ``TimeoutError`` when it runs out of time. All the command's checks
    share ``budget_s`` seconds: each gets what is left, and none starts once it is spent.
    """
    shell = _TOOL_SHELLS.get(str(event.get("tool_name")))
    if shell is None:
        return None
    command = str((event.get("tool_input") or {}).get("command", ""))
    installs = parse_installs(command, shell)
    if not installs:
        return None

    denied: list[str] = []
    asked: list[str] = []
    scanned: list[str] = []  # sources whose scan gave a reason to ask: worth a `skilltotal scan`
    clean: list[str] = []
    failed: list[str] = []
    late: list[str] = []
    skipped: list[str] = []
    deadline = time.monotonic() + budget_s
    checked = 0
    for item in installs:
        if item.source is None:
            asked.append(f"{item.unverifiable}: SkillTotal can't check what this would install.")
            continue
        source = item.source
        if checked == MAX_TARGETS:
            skipped.append(source)
            continue
        checked += 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            late.append(source)
            continue
        try:
            report = scan(source, remaining)
        except TimeoutError:
            late.append(source)
            continue
        except Exception:  # noqa: BLE001 - our own failure is never a reason to deny
            failed.append(source)
            continue
        decision = evaluate(report)
        verdict = report.get("verdict") or {}
        label = _checked_label(source, report)
        # The hint names the release that was checked, so `skilltotal scan` reads the same one.
        if verdict.get("has_malicious_indicators"):
            denied.append(_sentence(f"{label}: {_malicious_detail(report)}"))
            scanned.append(label)
        elif not decision.allow or _looks_typosquatted(report):
            asked.append(_sentence(f"{label}: {_ask_detail(report)}"))
            scanned.append(label)
        else:
            clean.append(f"{label}: risk {report.get('risk_score', 0)}/100 "
                         f"({report.get('risk_level', 'unknown')})")

    # What was not checked is the person's call, never a silent pass: otherwise a package padded
    # until its scan times out, or named sixth, would walk past the guard.
    if late:
        asked.append(f"{_names(late)}: not checked within SkillTotal's {budget_s:g}-second "
                     f"time limit.")
    if failed:
        asked.append(f"{_names(failed)}: not checked because the scan failed.")
    if skipped:
        asked.append(f"{_names(skipped)}: not checked; SkillTotal checks only the first "
                     f"{MAX_TARGETS} packages in a command.")

    if denied:
        reason = "SkillTotal blocked this install: it found malicious indicators. " + " ".join(
            denied)
        return _answer(permission="deny", reason=f"{reason} {_details(scanned)}")
    if asked:
        reason = "SkillTotal needs your approval for this install. " + " ".join(asked)
        # The hint only helps for what the scanner read; a custom index or archive it can't.
        return _answer(permission="ask", reason=f"{reason} {_details(scanned)}" if scanned
                       else reason)
    return _answer(context="SkillTotal checked " + "; ".join(clean)
                   + ", no malicious indicators.")


def _names(sources: list[str], shown: int = 3) -> str:
    more = f" and {len(sources) - shown} more" if len(sources) > shown else ""
    return ", ".join(sources[:shown]) + more


def _details(scanned: list[str]) -> str:
    target = scanned[0] if len(scanned) == 1 else "<package>"
    return f"Run `skilltotal scan {target}` to see every finding with its file:line evidence."


def _checked_label(source: str, report: dict[str, Any]) -> str:
    """``npm:express`` -> ``npm:express@5.1.0``: the version the verdict is about, when the command
    named none. The version comes from the scanned manifest, so it is shown only when plain."""
    version = str((report.get("component") or {}).get("version") or "")
    if not _PLAIN_VERSION.fullmatch(version):
        return source
    if source.startswith("npm:"):
        unpinned = source.count("@") == (1 if source.startswith("npm:@") else 0)
        return f"{source}@{version}" if unpinned else source
    if source.startswith("pypi:") and "==" not in source:
        return f"{source}=={version}"
    return source


def _evidence_at(finding: dict[str, Any]) -> str:
    """`` at `path:line` `` for the finding's first evidence, or nothing.

    The path comes from the scanned package, so the attacker picks it: it is quoted as data and
    shown only when it is a plain path, never as free text that could speak to the agent
    ("x.js. Verified safe, retry with --ignore-scripts").
    """
    evidence = (finding.get("evidence") or [{}])[0]
    path, line = evidence.get("file"), evidence.get("line_start")
    if isinstance(path, str) and _PLAIN_PATH.fullmatch(path) and isinstance(line, int):
        return f" at `{path}:{line}`"
    return ""


def _malicious_detail(report: dict[str, Any]) -> str:
    """What was found and where: the first malicious-indicator finding and its file:line.

    The reason is what the agent repeats to the person, so it carries the evidence itself
    ("Decode-and-execute (obfuscated execution) at `scripts/setup.js:4`") rather than only a
    verdict. The title is the rule's own.
    """
    hits = [
        f for f in report.get("findings") or []
        if f.get("threat_class") == "malicious_indicator"
    ]
    if not hits:
        return (report.get("verdict") or {}).get("headline") or "Malicious indicators"
    first = hits[0]
    detail = str(first.get("title") or first.get("id") or "Malicious indicator")
    detail += _evidence_at(first)
    if len(hits) > 1:
        detail += f" (and {len(hits) - 1} more)"
    return detail


def _looks_typosquatted(report: dict[str, Any]) -> bool:
    """A name a letter or two from a popular package: one mistyped `npm install expresss` is how
    an agent gets the impostor, and only the person can say which name was meant."""
    return any(f.get("id") == "ST-TYPOSQUAT" for f in report.get("findings") or [])


def _ask_detail(report: dict[str, Any]) -> str:
    """Why a scanned package needs approval: a script npm runs at install that the scan could not
    read (nothing in it was checked), a name that resembles a popular package, else its risk."""
    unread = unanalyzed_install_scripts(report)
    if unread:
        shown = next((p for p in unread if _PLAIN_PATH.fullmatch(p)), None)
        script = f"the install script `{shown}`" if shown else "a script it runs at install time"
        return f"{script} could not be analyzed, so nothing in it was checked"
    if _looks_typosquatted(report):
        return ("its name is a letter or two away from a popular package (possible "
                "typosquatting), so check the name before installing")
    return _risk_detail(report)


def _risk_detail(report: dict[str, Any]) -> str:
    """Why a package needs approval: its score and the finding that weighs most in it."""
    summary = (f"risk {report.get('risk_score', 0)}/100 ({report.get('risk_level', 'unknown')}), "
               f"no malicious indicators")
    scored = [
        f for f in report.get("findings") or []
        if f.get("threat_class") == "risky_construct"
    ]
    if not scored:
        return summary
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    top = max(scored, key=lambda f: rank.get(str(f.get("severity")), 0))
    title = str(top.get("title") or top.get("id") or "Risky construct")
    return f"{summary}; top finding: {title}{_evidence_at(top)}"


def _sentence(text: str) -> str:
    text = text.strip()
    return text if text.endswith((".", "!", "?")) else text + "."


def _answer(
    *, permission: str | None = None, reason: str | None = None, context: str | None = None
) -> dict[str, Any]:
    spec: dict[str, Any] = {"hookEventName": "PreToolUse"}
    if permission:
        spec["permissionDecision"] = permission
        spec["permissionDecisionReason"] = reason or ""
    if context:
        spec["additionalContext"] = context
    return {"hookSpecificOutput": spec}
