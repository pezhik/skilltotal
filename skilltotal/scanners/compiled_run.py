"""Compiled or binary code the component starts, which no scanner of source can read.

A report that lists nothing risky covers the text the scan read. A component can ship the part
that runs in another form: Python bytecode with no ``.py`` beside it, or a native program. Two
things follow from one reading of the commands a component runs on its own or tells an agent to
run (npm lifecycle scripts and the scripts they start, agent instruction files, hooks, MCP launch
commands and other auto-run configuration):

* ``started_binaries`` names each such file. The engine reports the native programs among them
  as started and not analyzed (a coverage note: a server shipped as a compiled binary is common
  and honest, and the report must still say that nothing in it was checked).
* ``ST-BYTECODE-NO-SOURCE`` reports a command, or an import in the component's own code, that
  runs Python bytecode (``.pyc`` / ``.pyo``) shipped without its source. Python needs no bytecode
  file to run a module, and an interpreter writes one next to its source, so bytecode alone is a
  choice to ship the code unreadable. What the bytecode does is not known, so this is a risky
  construct, not a malicious indicator.

Bytecode with its source beside it (``tool.pyc`` next to ``tool.py``, ``__pycache__/`` next to
the modules it came from) is a build artifact and is never reported. Parsing only: nothing is
loaded or run, and no bytecode is read.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import PurePosixPath

from skilltotal.autorun import autorun_commands
from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.loaded_code import NPM_LIFECYCLE_SCRIPTS
from skilltotal.models import Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
)
from skilltotal.scanners.disguised_script import (
    SOURCE_AUTORUN,
    SOURCE_INSTALL,
    SOURCE_INSTRUCTION,
    _candidates,
)
from skilltotal.scanners.install_scripts import npm_install_commands
from skilltotal.scanners.skill_fetch_exec import _INSTRUCTION_FILE

R_BYTECODE_NO_SOURCE = "ST-BYTECODE-NO-SOURCE"

KIND_BYTECODE = "bytecode"
KIND_PROGRAM = "program"

_PY_BYTECODE = frozenset({".pyc", ".pyo"})
# A file a runtime is started on that holds compiled code: `python x.pyc`, `wasmtime x.wasm`,
# `node addon.node`, `mono tool.exe`. (An archive it is started on, `java -jar x.jar`, is read
# member by member: see skilltotal.archive_members.)
_COMPILED_SUFFIXES = frozenset({*_PY_BYTECODE, ".wasm", ".node", ".exe", ".dll", ".class"})
# A path run directly (`./bin/helper`): a program has no suffix, or one of these.
_PROGRAM_SUFFIXES = frozenset({"", ".exe", ".bin", ".run", ".out", ".elf", ".appimage", ".com"})

_PATH = r"((?:\$\{?[A-Za-z_][\w:.-]{0,60}\}?[\"']?[/\\])?[\w./@+\\-]{1,200})"
_RUNTIME_ON_FILE = re.compile(
    r"(?<![\w/.$-])(?:python[0-9.]{0,5}|pypy3?|node|nodejs|bun|deno|wasmtime|wasmer|wasm3"
    r"|wasmedge|mono|dotnet|wine)(?:\.exe)?[ \t]{1,4}"
    r"(?:(?:-{1,2}[\w-]{1,30}(?:=[^\s\"']{0,100})?|run|exec)[ \t]{1,4}){0,4}[\"']?" + _PATH
)
_DIRECT_RUN = re.compile(
    r"(?<![\w/.$@:=~-])((?:\./|\$\{?[A-Za-z_][\w:.-]{0,60}\}?[\"']?[/\\])[\w./@+\\-]{1,200})"
)
# What stands before a path that is itself the command: nothing (the start of the text, of a
# line, of a quoted or back-quoted command, of the next command in a chain), or a word that says
# to run it.
_COMMAND_POSITION = re.compile(
    r"(?i)(?:^|[\n`\"'(;|&]|\b(?:run|runs|running|execute|executes|launch|launches|start|starts"
    r"|invoke|call|exec|sudo|nohup|time|then|do)\b)[ \t]*$"
)
# A component starts a file or two this way; these only bound a crafted one.
_MAX_MATCHES_PER_TEXT = 200
_MAX_STARTED = 64
_MAX_ORPHANS = 16


@dataclass(frozen=True)
class StartedBinary:
    """One command that starts ``target``, a compiled or binary file inside the component."""

    target: str
    kind: str  # KIND_BYTECODE (Python bytecode without its source) or KIND_PROGRAM
    source: str  # SOURCE_INSTALL, SOURCE_INSTRUCTION or SOURCE_AUTORUN
    evidence: Evidence  # where the command is written


def bytecode_source(relpath: str) -> str:
    """Where the source of the Python bytecode file ``relpath`` belongs: ``x.py`` beside
    ``x.pyc``, and the folder above for a file in ``__pycache__``
    (``pkg/__pycache__/x.cpython-311.pyc`` came from ``pkg/x.py``)."""
    path = PurePosixPath(relpath)
    if path.parent.name == "__pycache__":
        return (path.parent.parent / (path.name.split(".", 1)[0] + ".py")).as_posix()
    return path.with_suffix(".py").as_posix()


def python_bytecode_without_source(index: FileIndex) -> list[str]:
    """The ``.pyc`` / ``.pyo`` files the index lists (``FileIndex.compiled``) whose source is not
    a file of the index. From the index alone, so a scanner can use it."""
    known = {f.relpath for f in index.files} | {*index.large, *index.minified, *index.own_outputs}
    return [
        relpath for relpath in index.compiled
        if relpath.lower().endswith(tuple(_PY_BYTECODE)) and bytecode_source(relpath) not in known
    ]


def started_binaries(index: FileIndex, unread: Callable[[str], bool]) -> list[StartedBinary]:
    """Every command in ``index`` that starts a compiled or binary file of the component:
    a runtime started on one (``python tools/x.pyc``, ``wasmtime x.wasm``) or a path run directly
    (``./bin/helper``, ``${CLAUDE_PLUGIN_ROOT}/bin/helper``).

    ``unread(relpath)`` says whether a relative path is a file of the component that the scan did
    not read as text; only such files are returned.
    """
    started: list[StartedBinary] = []
    seen: set[tuple[str, str, int]] = set()

    def consider(text: str, near: str, source: str, where: Callable[[re.Match[str]], Evidence]):
        if "/" not in text and "\\" not in text and not any(s in text for s in _COMPILED_SUFFIXES):
            return
        matches = [(m, False) for m in _RUNTIME_ON_FILE.finditer(text)]
        matches += [(m, True) for m in _DIRECT_RUN.finditer(text)]
        for k, (m, direct) in enumerate(matches):
            if k >= _MAX_MATCHES_PER_TEXT or len(started) >= _MAX_STARTED:
                return
            word = m.group(1).strip("\"'").rstrip(".,;:)")
            suffix = posixpath.splitext(word.replace("\\", "/"))[1].lower()
            if suffix not in (_PROGRAM_SUFFIXES if direct else _COMPILED_SUFFIXES):
                continue
            if direct and not _COMMAND_POSITION.search(text, max(0, m.start() - 60), m.start()):
                continue  # an argument of another command (`python thumb.py ./assets/x.bin`)
            for rel in _candidates(word, near):
                if not unread(rel):
                    continue
                evidence = where(m)
                key = (rel, evidence.file, evidence.line_start)
                if key not in seen:
                    seen.add(key)
                    kind = KIND_BYTECODE if suffix in _PY_BYTECODE else KIND_PROGRAM
                    started.append(StartedBinary(rel, kind, source, evidence))
                break

    for f in index.files:
        name = f.relpath.rsplit("/", 1)[-1]
        if name == "package.json":
            for _script, command, start, end in npm_install_commands(f, NPM_LIFECYCLE_SCRIPTS):
                consider(command, f.relpath, SOURCE_INSTALL,
                         lambda _m, f=f, start=start, end=end: f.evidence_for_span(start, end))
        elif f.relpath in index.install_scripts:
            consider(f.text, f.relpath, SOURCE_INSTALL, _in_file(f))
        elif _INSTRUCTION_FILE.search(f.relpath):
            consider(f.text, f.relpath, SOURCE_INSTRUCTION, _in_file(f))
    for command in autorun_commands(index).commands:
        if not command.is_http:
            consider(
                command.text, command.file.relpath, SOURCE_AUTORUN,
                lambda m, command=command: command.evidence(command.piece_at(m.start(1))),
            )
    return started


def _in_file(f: IndexedFile) -> Callable[[re.Match[str]], Evidence]:
    return lambda m: f.evidence_for_span(m.start(1), m.end(1))


def _imports_of(index: FileIndex, orphan: str) -> list[Evidence]:
    """Where the component's own Python code loads the bytecode file ``orphan``: an import of its
    module name from a file in the same folder or the folder above, or its file name in code."""
    path = PurePosixPath(orphan)
    module = re.escape(path.stem)
    folder = path.parent.as_posix()
    folder = "" if folder == "." else folder
    above = posixpath.dirname(folder)
    loads = re.compile(
        rf"(?m)^[ \t]*(?:import[ \t]+(?:[\w.]+\.)?{module}\b"
        rf"|from[ \t]+[\w.]*?\.?{module}[ \t]+import\b"
        rf"|from[ \t]+[\w.]+[ \t]+import[ \t]+(?:[\w ,]*,[ \t]*)?{module}\b)"
        rf"|[\"']{re.escape(path.name)}[\"']"
    )
    found: list[Evidence] = []
    for f in index.files:
        if f.suffix not in (".py", ".pyw") or path.stem not in f.text:
            continue
        if posixpath.dirname(f.relpath) not in (folder, above):
            continue
        m = loads.search(f.text)
        if m is not None and not f.in_comment(m.start()):
            found.append(f.evidence_for_span(m.start(), m.end()))
    return found


class CompiledRunScanner(Scanner):
    name = "compiled_run"
    rules = [
        RuleSpec(
            id=R_BYTECODE_NO_SOURCE,
            category="obfuscation",
            severity=Severity.MEDIUM,
            title="Runs Python bytecode shipped without its source",
            description=(
                "An install script, an agent instruction file, a hook or launch command, or the "
                "component's own Python code runs or imports a `.pyc` / `.pyo` file that has no "
                "`.py` beside it. Python does not need a bytecode file to run a module and "
                "writes one next to its source, so the code was shipped in a form a reader and "
                "a scanner of source cannot check. Bytecode is not analyzed: what this file does "
                "is not known."
            ),
            recommendation=(
                "Ask the publisher for the source, or decompile the file in isolation and read "
                "it before running the component."
            ),
            capability=None,  # what the bytecode can do is not known
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        # From the index alone: the engine lists there the bytecode the walk found and the
        # bytecode a command starts from a `__pycache__` folder, which the walk never enters.
        orphans = python_bytecode_without_source(index)
        if not orphans:
            return ScanResult()
        evidence: list[Evidence] = []
        for run in started_binaries(index, set(orphans).__contains__):
            if run.kind == KIND_BYTECODE:
                evidence.append(_noted(run.evidence, run.target))
        for orphan in sorted(orphans)[:_MAX_ORPHANS]:
            if PurePosixPath(orphan).parent.name == "__pycache__":
                continue  # Python never imports a cached file whose source is gone
            evidence.extend(_noted(ev, orphan) for ev in _imports_of(index, orphan))
        if not evidence:
            return ScanResult()
        return ScanResult(
            findings=[_finding_from_rule(self.rules[0], evidence[:MAX_EVIDENCE_SCANNED])]
        )


def _noted(evidence: Evidence, target: str) -> Evidence:
    note = f"  [runs {target}: bytecode shipped without its source]"
    return replace(evidence, snippet=evidence.snippet[:180] + note)
