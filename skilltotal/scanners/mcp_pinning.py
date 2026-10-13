"""MCP servers launched at whatever release is current.

A client's MCP configuration that starts a server with ``npx -y pkg``, ``npx -y pkg@latest``,
``uvx pkg`` or ``docker run image:latest`` fetches the newest release at every launch: the server
that runs next week is not the one any scan saw, and a compromised release reaches every user on
their next start. It is also how most MCP servers are documented, so this is one review note per
report, never a finding and never scored. A version (``pkg@1.2.3``, ``pkg==1.2.3``), an image
tag or digest, or a server started from the component's own files is not noted.
"""

from __future__ import annotations

import re

from skilltotal.autorun import KIND_MCP_SERVER, autorun_commands
from skilltotal.file_index import FileIndex
from skilltotal.scanners.base import Scanner, ScanResult, aggregated_review

TITLE = "MCP server runs whatever release is current"

_NPM_EXACT = re.compile(r"^(?:@[^/@\s]+/)?[^@\s/]+@\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_PY_EXACT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?(?:==|@)\d[0-9A-Za-z.+!-]*$")
# npx/bunx/pnpx and dlx options that take a value (the package is the next word after them).
_NPM_VALUE_FLAGS = frozenset({"-p", "--package", "-c", "--call", "--registry", "--cache",
                              "--prefix", "-w", "--workspace"})
_UV_VALUE_FLAGS = frozenset({"--from", "--with", "--python", "-p", "--index", "--index-url",
                             "--extra-index-url", "--with-requirements", "--constraints", "-c"})
_DOCKER_VALUE_FLAGS = frozenset({"-e", "--env", "-v", "--volume", "-p", "--publish", "--name",
                                 "--network", "-w", "--workdir", "-u", "--user", "--env-file",
                                 "--mount", "--entrypoint", "--platform", "-l", "--label",
                                 "--add-host", "--cpus", "-m", "--memory", "--pull", "-h",
                                 "--hostname", "--restart", "--runtime", "--cap-add",
                                 "--cap-drop", "--device", "--gpus", "--security-opt"})


class McpPinningScanner(Scanner):
    name = "mcp_pinning"
    rules = []

    def scan(self, index: FileIndex) -> ScanResult:
        places: list[tuple[str, int | None]] = []
        for command in autorun_commands(index).commands:
            if command.kind != KIND_MCP_SERVER or not command.pieces:
                continue
            words = [p.text for p in command.pieces]
            if _unpinned(words):
                first = command.pieces[0]
                line = command.file.evidence_for_span(first.start, first.end).line_start
                places.append((command.file.relpath, line))
        if not places:
            return ScanResult()
        return ScanResult(needs_review=[aggregated_review(
            category="supply_chain",
            title=TITLE,
            places=places,
            what="MCP server launch command(s) fetch the newest release at every start",
            advice=(
                "The release that runs later is not the one checked now. Pin a version "
                "(pkg@1.2.3, pkg==1.2.3, image:tag or @sha256) so the checked release is the "
                "one that runs."
            ),
        )])


def _unpinned(words: list[str]) -> bool:
    program = words[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    program = re.sub(r"\.(?:cmd|exe|ps1)$", "", program)
    args = words[1:]
    if program in ("npx", "bunx", "pnpx"):
        return _npm_unpinned(args)
    if program in ("pnpm", "yarn") and args[:1] == ["dlx"]:
        return _npm_unpinned(args[1:])
    if program == "uvx":
        return _py_unpinned(args)
    if program == "uv" and args[:2] == ["tool", "run"]:
        return _py_unpinned(args[2:])
    if program == "pipx" and args[:1] == ["run"]:
        return _py_unpinned(args[1:])
    if program in ("docker", "podman") and args[:1] == ["run"]:
        return _image_unpinned(args[1:])
    return False


def _npm_unpinned(args: list[str]) -> bool:
    packages: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-p", "--package"):
            packages.extend(args[i + 1:i + 2])
            i += 2
        elif arg.startswith("--package="):
            packages.append(arg.split("=", 1)[1])
            i += 1
        elif arg.startswith("-"):
            i += 2 if arg in _NPM_VALUE_FLAGS and "=" not in arg else 1
        else:
            packages = packages or [arg]
            break
    return any(_registry_spec(p) and not _NPM_EXACT.match(p) for p in packages)


def _registry_spec(spec: str) -> bool:
    """A package from the registry, not a path, URL or repository."""
    return bool(spec) and not spec.startswith((".", "/", "~", "file:", "http:", "https:", "git",
                                               "github:", "$"))


def _py_unpinned(args: list[str]) -> bool:
    spec = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--from":
            spec = args[i + 1] if i + 1 < len(args) else None
            break
        if arg.startswith("--from="):
            spec = arg.split("=", 1)[1]
            break
        if arg.startswith("-"):
            i += 2 if arg in _UV_VALUE_FLAGS and "=" not in arg else 1
            continue
        spec = arg
        break
    return bool(spec) and _registry_spec(spec) and not _PY_EXACT.match(spec)


def _image_unpinned(args: list[str]) -> bool:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("-"):
            i += 2 if arg in _DOCKER_VALUE_FLAGS and "=" not in arg else 1
            continue
        if "$" in arg or "@sha256:" in arg:
            return False
        name = arg.rsplit("/", 1)[-1]
        return ":" not in name or name.endswith(":latest")
    return False
