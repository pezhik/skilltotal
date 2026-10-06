"""Claude Code PreToolUse hook: check a package before the agent installs it.

The SkillTotal plugin runs this before every Bash command the agent wants to execute. It finds the
packages an install command would bring in (``npx``, ``npm install``, ``pip install``, ``uvx``,
``claude mcp add ... -- npx ...``), scans each one, and answers in Claude Code's hook format:

* a package with malicious indicators: ``deny``, with the reason shown to the agent;
* a package whose scored risk is high or critical: ``ask``, so the person decides;
* everything clean: no decision (the normal permission flow applies) plus a one-line note for the
  agent.

A scan that fails (registry down, package not found) never blocks the install: the hook guards the
person's work, it must not break it. Pure library code: the CLI reads stdin and prints the answer.
"""

from __future__ import annotations

import re
import shlex
import time
from collections.abc import Callable
from typing import Any

from skilltotal.guard import evaluate

MAX_TARGETS = 5
# How long the agent waits for all checks of one command. A large package can take longer to scan
# than anyone will wait before every install; past this the install goes ahead, marked unchecked.
DEFAULT_BUDGET_S = 30.0

# Commands that bring in npm packages: the subcommand that installs, or a runner that fetches.
_NPM_INSTALL = {"npm": {"install", "i", "add", "isntall"}, "pnpm": {"add", "install", "i"},
                "yarn": {"add"}, "bun": {"add", "install", "i"}}
_NPM_RUNNERS = {"npx", "bunx"}
_PY_INSTALLERS = {"pip", "pip3"}

# Flags whose next token is a value, not a package.
_NPM_VALUE_FLAGS = {"--registry", "--prefix", "--cache", "--tag", "-w", "--workspace",
                    "--userconfig"}
_PIP_VALUE_FLAGS = {"-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i",
                    "--index-url", "--extra-index-url", "-t", "--target", "--prefix", "-f",
                    "--find-links", "--python", "--root", "--platform", "--python-version"}
_UV_VALUE_FLAGS = {"--python", "-p", "--with", "--index", "--index-url", "--extra-index-url",
                   "--group", "--extra", "--package"}

_SEGMENT_SPLIT = re.compile(r"&&|\|\||[;|\n]")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_PY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")
_NPM_NAME = re.compile(r"^(?:@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$", re.IGNORECASE)


def install_targets(command: str) -> list[str]:
    """Package sources (``npm:name`` / ``pypi:name``) an install command would bring in."""
    found: list[str] = []
    for segment in _SEGMENT_SPLIT.split(command or ""):
        try:
            tokens = shlex.split(segment, posix=True)
        except ValueError:
            continue  # unbalanced quotes: not something we can read reliably
        for source in _targets_in(_strip_prefix(tokens)):
            if source not in found:
                found.append(source)
    return found[:MAX_TARGETS]


def _strip_prefix(tokens: list[str]) -> list[str]:
    i = 0
    while i < len(tokens) and (_ENV_ASSIGN.match(tokens[i]) or tokens[i] in ("sudo", "env")):
        i += 1
    return tokens[i:]


def _targets_in(tokens: list[str]) -> list[str]:
    if not tokens:
        return []
    head, rest = tokens[0], tokens[1:]
    if head == "claude" and rest[:2] == ["mcp", "add"] and "--" in rest:
        return _targets_in(_strip_prefix(rest[rest.index("--") + 1:]))
    if head in _NPM_RUNNERS:
        return _npx(rest)
    if head == "pnpm" and rest[:1] == ["dlx"]:
        return _npx(rest[1:])
    if head in _NPM_INSTALL and rest and rest[0] in _NPM_INSTALL[head]:
        return [f"npm:{n}" for n in _npm_args(rest[1:])]
    if head in ("python", "python3", "py") and rest[:3] == ["-m", "pip", "install"]:
        return [f"pypi:{n}" for n in _pip_args(rest[3:], _PIP_VALUE_FLAGS)]
    if head in _PY_INSTALLERS and rest[:1] == ["install"]:
        return [f"pypi:{n}" for n in _pip_args(rest[1:], _PIP_VALUE_FLAGS)]
    if head == "uv" and rest[:2] == ["pip", "install"]:
        return [f"pypi:{n}" for n in _pip_args(rest[2:], _PIP_VALUE_FLAGS)]
    if head == "uv" and rest[:1] == ["add"]:
        return [f"pypi:{n}" for n in _pip_args(rest[1:], _UV_VALUE_FLAGS)]
    if head == "uvx":
        return _uvx(rest)
    if head == "pipx" and rest[:1] in (["install"], ["run"]):
        names = _pip_args(rest[1:], _UV_VALUE_FLAGS)
        return [f"pypi:{names[0]}"] if names else []
    return []


def _npx(args: list[str]) -> list[str]:
    """``npx [-y] [-p pkg] pkg args``: the explicit ``-p`` package, else the first positional."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-p", "--package") and i + 1 < len(args):
            name = _npm_name(args[i + 1])
            return [f"npm:{name}"] if name else []
        if arg.startswith("--package="):
            name = _npm_name(arg.split("=", 1)[1])
            return [f"npm:{name}"] if name else []
        if arg.startswith("-"):
            i += 1
            continue
        name = _npm_name(arg)
        return [f"npm:{name}"] if name else []
    return []


def _npm_args(args: list[str]) -> list[str]:
    names: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in _NPM_VALUE_FLAGS:
            skip = True
            continue
        if arg.startswith("-"):
            continue
        name = _npm_name(arg)
        if name:
            names.append(name)
    return names


def _npm_name(spec: str) -> str | None:
    """``@scope/name@1.2`` -> ``@scope/name``; a path, URL or git spec is not a registry name."""
    if spec.startswith((".", "/", "~", "file:", "git", "http", "link:", "workspace:")):
        return None
    name = spec.rsplit("@", 1)[0] if spec.count("@") > (1 if spec.startswith("@") else 0) else spec
    return name if _NPM_NAME.match(name) else None


def _pip_args(args: list[str], value_flags: set[str]) -> list[str]:
    names: list[str] = []
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in value_flags:
            skip = True
            continue
        if arg.startswith("-"):
            continue
        name = _py_name(arg)
        if name:
            names.append(name)
    return names


def _py_name(spec: str) -> str | None:
    """``fastapi[standard]>=0.110`` -> ``fastapi``; a path, URL, wheel or VCS spec is skipped."""
    if spec.startswith((".", "/", "~")) or "://" in spec or spec.startswith("git+"):
        return None
    if spec.endswith((".whl", ".tar.gz", ".zip")) or "/" in spec or "\\" in spec:
        return None
    m = _PY_NAME.match(spec)
    return m.group(0) if m else None


def _uvx(args: list[str]) -> list[str]:
    """``uvx [--from pkg] tool args``: ``--from`` names the package, else the tool does."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--from" and i + 1 < len(args):
            name = _py_name(args[i + 1])
            return [f"pypi:{name}"] if name else []
        if arg in _UV_VALUE_FLAGS:
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        name = _py_name(arg)
        return [f"pypi:{name}"] if name else []
    return []


Scan = Callable[[str, float], dict[str, Any]]


def hook_response(
    event: dict[str, Any], scan: Scan, budget_s: float = DEFAULT_BUDGET_S
) -> dict[str, Any] | None:
    """Claude Code's answer for one PreToolUse event, or None to stay silent.

    ``scan(source, timeout)`` returns a serialized report (``Report.to_dict()``) for a source such
    as ``npm:name``, or raises ``TimeoutError`` when it runs out of time. All the command's checks
    share ``budget_s`` seconds: each gets what is left, and none starts once it is spent.
    """
    if event.get("tool_name") != "Bash":
        return None
    command = str((event.get("tool_input") or {}).get("command", ""))
    targets = install_targets(command)
    if not targets:
        return None

    denied: list[str] = []
    asked: list[str] = []
    clean: list[str] = []
    failed: list[str] = []
    late: list[str] = []
    deadline = time.monotonic() + budget_s
    for source in targets:
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
            denied.append(f"{summary}. {verdict.get('headline') or 'Malicious indicators'}")
        elif not decision.allow:
            asked.append(f"{summary}. {'; '.join(decision.reasons)}")
        else:
            clean.append(summary)

    details = "Run `skilltotal scan <package>` for the file:line evidence."
    if denied:
        reason = "SkillTotal found malicious indicators before install. " + " ".join(denied)
        return _answer(permission="deny", reason=f"{reason} {details}")
    if asked:
        reason = "SkillTotal rates this package high risk. " + " ".join(asked)
        return _answer(permission="ask", reason=f"{reason} {details}")
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
