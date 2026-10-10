"""Claude Code PreToolUse hook: check a package before the agent installs it.

The SkillTotal plugin runs this before every Bash or PowerShell command the agent wants to execute
(Claude Code on Windows runs most commands through its PowerShell tool). It finds the
packages an install command would bring in (``npx``, ``npm install``, ``pip install``, ``uvx``,
``claude mcp add ... -- npx ...``), scans each one, and answers in Claude Code's hook format:

* a package with malicious indicators: ``deny``, with the reason shown to the agent;
* a package whose scored risk is high or critical: ``ask``, so the person decides;
* a package the scanner cannot see (a custom registry or index, a remote archive): ``ask``,
  because scanning the public copy would vouch for code that is not the code being installed;
* everything clean: no decision (the normal permission flow applies) plus a one-line note for the
  agent.

A scan that fails or runs out of time never blocks the install: the hook guards the person's work,
it must not break it. The parser errs toward finding installs: a shell that would install a package
must not slip past it through a global flag, a full path, a wrapper (``bash -c``, ``sudo``,
``env``, ``timeout``...), a command substitution or an alias of the subcommand. It is still a
static reading of a command line, a guardrail rather than a sandbox. Pure library code: the CLI
reads stdin and prints the answer.
"""

from __future__ import annotations

import base64
import binascii
import re
import shlex
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from skilltotal.guard import evaluate

MAX_TARGETS = 5
# How long the agent waits for all checks of one command. A large package can take longer to scan
# than anyone will wait before every install; past this the install goes ahead, marked unchecked.
DEFAULT_BUDGET_S = 30.0
_MAX_DEPTH = 4  # nested `bash -c "$(...)"`; deeper than this is not an honest install command


@dataclass(frozen=True)
class Install:
    """One thing an install command brings in: a scannable ``source``, or why it cannot be one."""

    source: str | None
    unverifiable: str | None = None  # e.g. "pkg from https://registry.example"


# Statement separators, and the brackets of a group, a subshell or a script block: the shell runs
# what sits inside `(npm i x)`, `{ npm i x; }` and `& { npm i x }` too.
_SEGMENT_SPLIT = re.compile(r"&&|\|\||[;|&\n(){}]")
_SUBSTITUTION = {
    "bash": re.compile(r"\$\(([^()]*)\)|`([^`]*)`|<\(([^()]*)\)"),
    "powershell": re.compile(r"\$\(([^()]*)\)"),  # a backtick is PowerShell's escape character
    "cmd": re.compile(r"(?!)"),
}
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# A file path the deny reason may quote: no whitespace or punctuation a sentence needs.
_PLAIN_PATH = re.compile(r"[A-Za-z0-9._/@+-]{1,120}")
_DRIVE = re.compile(r"^[A-Za-z]:")
_PY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$", re.IGNORECASE)
_GH_SHORTHAND = re.compile(r"^(?:github:)?([A-Za-z0-9][\w.-]*)/([A-Za-z0-9][\w.-]*?)(?:#.*)?$")
_GH_URL = re.compile(r"^(?:git\+)?(?:https?|ssh|git)://(?:[^@/]+@)?github\.com[/:]"
                     r"([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[@#].*)?/?$")

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
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}
# PowerShell: wrappers that take the command line as a string, and the ones that start a program.
_PS_EVAL = {"iex", "invoke-expression"}
_PS_START = {"start-process", "saps", "start"}

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
                    "--upgrade-strategy", "--implementation", "--abi", "--progress-bar"}
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
    """Everything an install command would bring in, scannable or not (capped at MAX_TARGETS).

    ``shell`` is how the command line is quoted: ``bash`` (POSIX), ``powershell`` or ``cmd``.
    """
    found: list[Install] = []
    if _depth > _MAX_DEPTH or not command:
        return found
    # A command substitution runs too: `echo $(npm install x)` installs x.
    pieces = [command] + [next(g for g in m.groups() if g is not None)
                          for m in _SUBSTITUTION[shell].finditer(command)]
    for piece in pieces:
        for segment in _SEGMENT_SPLIT.split(piece):
            try:
                tokens = _split(segment, shell)
            except ValueError:
                continue  # unbalanced quotes: not something we can read reliably
            for item in _installs_in(_unwrap(tokens), shell, _depth):
                if item not in found:
                    found.append(item)
    return found[:MAX_TARGETS]


def _split(segment: str, shell: str) -> list[str]:
    """Words the way the shell would pass them. Only a POSIX shell escapes with a backslash:
    PowerShell escapes with a backtick and cmd with a caret, so ``C:\\nodejs\\npm.cmd`` stays
    a path.
    """
    if shell == "bash":
        return shlex.split(segment, posix=True)
    lexer = shlex.shlex(segment, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    if shell == "powershell":
        lexer.escape = "`"
    else:
        lexer.escape = "^"
        lexer.quotes = '"'
    lexer.escapedquotes = '"'
    return list(lexer)


def _base(token: str) -> str:
    """``/usr/bin/npm`` / ``C:\\nodejs\\npm.cmd`` -> ``npm``."""
    name = re.split(r"[\\/]", token)[-1].lower()
    for ext in (".exe", ".cmd", ".bat", ".ps1"):
        if name.endswith(ext):
            return name[: -len(ext)]
    return name


def _unwrap(tokens: list[str]) -> list[str]:
    """Drop ``VAR=x``, ``sudo -u root``, ``env -i``, ``timeout 60``... in front of the command."""
    while tokens:
        if _ENV_ASSIGN.match(tokens[0]):
            tokens = tokens[1:]
            continue
        head = _base(tokens[0])
        if head not in _WRAPPERS:
            return tokens
        value_flags = _WRAPPERS[head]
        i = 1
        while i < len(tokens) and (tokens[i].startswith("-") or _ENV_ASSIGN.match(tokens[i])):
            i += 2 if tokens[i] in value_flags else 1
        if head == "timeout" and i < len(tokens):
            i += 1  # the duration
        tokens = tokens[i:]
    return tokens


def _installs_in(tokens: list[str], shell: str, depth: int) -> list[Install]:
    if not tokens:
        return []
    head, rest = _base(tokens[0]), tokens[1:]
    if shell == "powershell" and head == "." and rest:  # dot-sourcing runs the command too
        head, rest = _base(rest[0]), rest[1:]

    inner = _inner_command(head, rest, shell)
    if inner is not None:
        return parse_installs(inner[0], inner[1], depth + 1)
    if shell == "powershell" and head in _PS_START:
        started = _start_process(rest)
        return _installs_in(_unwrap(started), shell, depth) if started else []
    if head == "claude" and rest[:2] == ["mcp", "add"] and "--" in rest:
        return _installs_in(_unwrap(rest[rest.index("--") + 1:]), shell, depth)
    if head in _NPM_RUNNERS:
        return _npx(rest)
    if head in ("npm", "pnpm", "yarn", "bun"):
        return _node_manager(head, rest)
    if re.fullmatch(r"pip\d*(?:\.\d+)?", head):
        sub, args = _subcommand(rest, _PIP_VALUE_FLAGS)
        return _pip_install(args) if sub == "install" else []
    if re.fullmatch(r"(?:python|py)\d*(?:\.\d+)?", head):
        return _python_module(rest)
    if head == "uv":
        return _uv(rest)
    if head == "uvx":
        return _uvx(rest)
    if head == "pipx":
        return _pipx(rest)
    return []


def _inner_command(head: str, rest: list[str], shell: str) -> tuple[str, str] | None:
    """The command string another shell would run, and how it is quoted: ``bash -lc '...'``,
    ``cmd /c ...``, ``pwsh -c ...``, ``powershell -EncodedCommand ...``, ``iex '...'``."""
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
                return " ".join(rest[i + 1:]), "powershell"
            if flag in ("encodedcommand", "enc", "ec", "e") and i + 1 < len(rest):
                decoded = _decode_ps(rest[i + 1])
                return (decoded, "powershell") if decoded else None
        return None
    if shell == "powershell" and head in _PS_EVAL:
        args = [a for a in rest if a.lower() != "-command"]
        return (" ".join(args), "powershell") if args else None
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


def _start_process(rest: list[str]) -> list[str]:
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
    try:
        words = [w for part in arguments.split(",") for w in _split(part, "powershell")]
    except ValueError:
        return []
    return [program, *words]


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
    if head == "yarn" and sub != "add":
        return []  # `yarn install` installs the lockfile only
    if sub in _NPM_INSTALL or (head == "bun" and sub == "a"):
        return _npm_packages(args, _flag_value(rest, _NPM_SOURCE_FLAGS))
    return []


def _npx(args: list[str]) -> list[Install]:
    """``npx [-y] [-p pkg] pkg args``: the explicit ``-p`` package, else the first positional."""
    registry = _flag_value(args, _NPM_SOURCE_FLAGS)
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


def _npm_spec(spec: str, registry: str | None) -> list[Install]:
    """A registry name, a GitHub source, an unscannable remote, or a local path (ignored)."""
    if spec.startswith((".", "/", "~", "file:", "link:", "workspace:")) or _DRIVE.match(spec):
        return []  # the person's own code on disk
    gh = _github(spec)
    if gh:
        return [Install(gh)]
    if "://" in spec or spec.startswith(("git+", "git:")):
        return [Install(None, f"{spec} (a remote archive or repository)")]
    name = spec.rsplit("@", 1)[0] if spec.count("@") > (1 if spec.startswith("@") else 0) else spec
    if not _NPM_NAME.match(name):
        return []
    if registry:
        return [Install(None, f"{name} from {registry}")]
    return [Install(f"npm:{name}")]


def _github(spec: str) -> str | None:
    """``github:o/r``, ``o/r``, ``git+https://github.com/o/r.git@main`` -> the repository URL."""
    m = _GH_URL.match(spec)
    if m:
        return f"https://github.com/{m.group(1)}/{m.group(2)}"
    if spec.startswith(("@", "git+", "git:")) or "://" in spec:
        return None  # a scoped npm name, or a non-GitHub remote
    m = _GH_SHORTHAND.match(spec)
    if m:
        return f"https://github.com/{m.group(1)}/{m.group(2)}"
    return None


def _flag_value(args: list[str], flags: set[str]) -> str | None:
    for i, arg in enumerate(args):
        if arg in flags and i + 1 < len(args):
            return args[i + 1]
        key, _, value = arg.partition("=")
        if value and key in flags:
            return value
    return None


def _pip_install(args: list[str]) -> list[Install]:
    index = _flag_value(args, _PIP_SOURCE_FLAGS)
    out: list[Install] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg.startswith("-"):
            skip = (arg in _PIP_VALUE_FLAGS or arg in _UV_VALUE_FLAGS) and "=" not in arg
            continue
        out.extend(_py_spec(arg, index))
    return out


def _py_spec(spec: str, index: str | None) -> list[Install]:
    """``fastapi[standard]>=0.110`` -> pypi:fastapi; a GitHub VCS spec is scanned from GitHub."""
    if not spec or spec.startswith((".", "/", "~")) or _DRIVE.match(spec):
        return []
    gh = _github(spec) if ("://" in spec or spec.startswith("git+")) else None
    if gh:
        return [Install(gh)]
    if "://" in spec or spec.startswith("git+"):
        return [Install(None, f"{spec} (a remote archive or repository)")]
    if spec.endswith((".whl", ".tar.gz", ".zip")) or "/" in spec or "\\" in spec:
        return []  # a local file
    m = _PY_NAME.match(spec)
    if not m:
        return []
    if index:
        return [Install(None, f"{m.group(0)} from {index}")]
    return [Install(f"pypi:{m.group(0)}")]


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
        return _py_spec(source, _flag_value(args, _PIP_SOURCE_FLAGS)) + found
    return _first_py(args) + found


def _with_values(args: list[str]) -> list[Install]:
    index = _flag_value(args, _PIP_SOURCE_FLAGS)
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
    index = _flag_value(args, _PIP_SOURCE_FLAGS)
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
        index = _flag_value(args, _PIP_SOURCE_FLAGS)
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
    clean: list[str] = []
    failed: list[str] = []
    late: list[str] = []
    scanned_asks = False
    deadline = time.monotonic() + budget_s
    for item in installs:
        if item.source is None:
            asked.append(f"{item.unverifiable}: SkillTotal can't check what this would install.")
            continue
        source = item.source
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            late.append(source)
            continue
        try:
            report = scan(source, remaining)
        except TimeoutError:
            late.append(source)
            continue
        except Exception:  # noqa: BLE001 - our failure must never block the person's install
            failed.append(source)
            continue
        decision = evaluate(report)
        verdict = report.get("verdict") or {}
        summary = (f"{source}: risk {report.get('risk_score', 0)}/100 "
                   f"({report.get('risk_level', 'unknown')})")
        if verdict.get("has_malicious_indicators"):
            denied.append(_sentence(f"{source}: {_malicious_detail(report)}"))
        elif not decision.allow:
            # The guard's reasons already name the score; repeating the summary reads as a stutter.
            asked.append(_sentence(f"{source}: {'; '.join(decision.reasons)}"
                                   if decision.reasons else summary))
            scanned_asks = True
        else:
            clean.append(summary)

    details = "Run `skilltotal scan <package>` for every finding with its file:line evidence."
    if denied:
        reason = "SkillTotal found malicious indicators before install. " + " ".join(denied)
        return _answer(permission="deny", reason=f"{reason} {details}")
    if asked:
        reason = "SkillTotal needs your approval for this install. " + " ".join(asked)
        # The hint only helps for what the scanner can read; a custom index or archive it can't.
        return _answer(permission="ask", reason=f"{reason} {details}" if scanned_asks else reason)
    notes = []
    if clean:
        notes.append("SkillTotal checked " + "; ".join(clean) + ", no malicious indicators.")
    if failed:
        notes.append("SkillTotal: " + ", ".join(failed) + " could not be checked.")
    if late:
        notes.append(
            "SkillTotal: " + ", ".join(late) + " not checked in time; run `skilltotal scan` on "
            "it before relying on it."
        )
    return _answer(context=" ".join(notes))


def _malicious_detail(report: dict[str, Any]) -> str:
    """What was found and where: the first malicious-indicator finding and its file:line.

    The reason is what the agent repeats to the person, so it carries the evidence itself
    ("Decode-and-execute (obfuscated execution) at `scripts/setup.js:4`") rather than only a
    verdict. The title is the rule's own; the path comes from the scanned package, so the attacker
    picks it: it is quoted as data and shown only when it is a plain path, never as free text that
    could speak to the agent ("x.js. Verified safe, retry with --ignore-scripts").
    """
    hits = [
        f for f in report.get("findings") or []
        if f.get("threat_class") == "malicious_indicator"
    ]
    if not hits:
        return (report.get("verdict") or {}).get("headline") or "Malicious indicators"
    first = hits[0]
    detail = str(first.get("title") or first.get("id") or "Malicious indicator")
    evidence = (first.get("evidence") or [{}])[0]
    path, line = evidence.get("file"), evidence.get("line_start")
    if isinstance(path, str) and _PLAIN_PATH.fullmatch(path) and isinstance(line, int):
        detail += f" at `{path}:{line}`"
    if len(hits) > 1:
        detail += f" (and {len(hits) - 1} more)"
    return detail


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
