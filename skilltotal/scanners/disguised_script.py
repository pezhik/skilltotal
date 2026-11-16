"""A script started under a name that hides it: ``node assets/logo.png``.

An interpreter runs whatever file it is given, whatever the file is called. A package whose
``postinstall`` is ``node assets/logo.png`` runs JavaScript at install time, and a skill that tells
the agent to run ``python3 assets/template.docx`` runs Python, while a reader of the file list, and
every rule that picks files by suffix, sees an image and a document.

Two things follow from one reading of the commands a component runs on its own or tells an agent
to run (npm lifecycle scripts and the scripts they start, agent instruction files, hooks and other
auto-run configuration):

* ``disguised_runs`` names each such file and the language it is started as. The engine re-reads
  the file as that language (``FileIndex.reading_as``), so every rule judges what it does.
* ``ST-DISGUISED-SCRIPT`` reports the command itself. An honest project has no reason to keep a
  script under a media or document name, but the name alone proves nothing about what the script
  does, so it is a risky construct; the payload is judged by the rules that now read it.

Only a file that exists in the component and whose suffix is one of ``DISGUISE_SUFFIXES`` counts:
``node build.js logo.png`` passes an image to a script and is not this. Parsing only.
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Callable
from dataclasses import dataclass

from skilltotal.autorun import autorun_commands
from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.loaded_code import NPM_LIFECYCLE_SCRIPTS
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
)
from skilltotal.scanners.install_scripts import npm_install_commands
from skilltotal.scanners.skill_fetch_exec import _INSTRUCTION_FILE

R_DISGUISED = "ST-DISGUISED-SCRIPT"

# Names of images, documents, media, fonts, archives and data files: nobody keeps a script under
# one by accident. Markdown, plain text and HTML are left out: they are read as what they are
# (instructions, pages), and a file can be read as one language only.
DISGUISE_SUFFIXES = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".icns", ".webp", ".svg", ".tif", ".tiff",
    ".psd",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".rtf", ".epub",
    ".mp3", ".mp4", ".wav", ".ogg", ".avi", ".mov", ".mkv", ".flac", ".webm",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".zip", ".gz", ".tgz", ".tar", ".bz2", ".xz", ".7z", ".rar",
    ".csv", ".log", ".dat", ".data", ".bin", ".tmp", ".bak", ".css", ".map",
})

SOURCE_INSTALL = "install"
SOURCE_INSTRUCTION = "instruction"
SOURCE_AUTORUN = "autorun"

# An interpreter started on a file: `node assets/logo.png`, `python3 -u tools/x.docx`,
# `bash "${CLAUDE_PLUGIN_ROOT}/assets/icon.png"`.
_RUNS_FILE = re.compile(
    r"(?<![\w/.$-])((?:ba|z|da|k)?sh|node|nodejs|python[0-9.]{0,5})(?:\.exe)?[ \t]{1,4}"
    r"((?:-{1,2}[\w-]{1,30}(?:=[^\s\"']{0,100})?[ \t]{1,4}){0,4})"
    r"[\"']?((?:\$\{?[A-Za-z_][\w:.-]{0,60}\}?[\"']?[/\\])?[\w./@+\\-]{1,200})"
)
# Options after which the next word is inline code or a module name, not a file.
_NOT_A_FILE_AFTER = {
    "node": frozenset({"-e", "-p", "--eval", "--print", "-r", "--require", "--import",
                       "--loader"}),
    "python": frozenset({"-c", "-m"}),
    "shell": frozenset({"-c"}),
}
_LANGUAGE = {"node": ".js", "python": ".py", "shell": ".sh"}
_ROOT_VARIABLE = re.compile(r"^\$\{?[A-Za-z_][\w:.-]*\}?[\"']?[/\\]")
# A component starts a file or two this way; these only bound a crafted one.
_MAX_MATCHES_PER_TEXT = 200
_MAX_RUNS = 64


@dataclass(frozen=True)
class DisguisedRun:
    """One command that starts ``target`` (a path inside the component) with an interpreter."""

    target: str
    language: str  # ".js", ".py" or ".sh"
    source: str  # SOURCE_INSTALL, SOURCE_INSTRUCTION or SOURCE_AUTORUN
    evidence: Evidence  # where the command is written
    # False when the file is not among the files the scan read (binary content, too large).
    read: bool = True


def _family(interpreter: str) -> str:
    if interpreter.startswith("node"):
        return "node"
    return "python" if interpreter.startswith("python") else "shell"


def _real_suffix(relpath: str) -> str:
    return posixpath.splitext(relpath)[1].lower()


def _candidates(word: str, near: str) -> list[str]:
    """Relative paths ``word`` may name: from the folder of ``near`` (the file the command is
    written in), each folder above it, and the component root."""
    word = _ROOT_VARIABLE.sub("", word).replace("\\", "/")
    if not word or word.startswith(("/", "~")) or ":" in word:
        return []
    parts = near.split("/")[:-1]
    out: list[str] = []
    for k in range(len(parts), -1, -1):
        rel = posixpath.normpath("/".join([*parts[:k], word]))
        if rel != "." and rel != ".." and not rel.startswith("../") and rel not in out:
            out.append(rel)
    return out


def disguised_runs(
    index: FileIndex, on_disk: Callable[[str], bool] | None = None
) -> list[DisguisedRun]:
    """Every command in ``index`` that starts a file of the component named like an image, a
    document or another non-code file (``DISGUISE_SUFFIXES``) with node, python or a shell.

    Without ``on_disk`` only files the index holds count, so the result depends on the index
    alone. With it (the engine passes a check of the component folder), a file the index does not
    hold but that exists is returned too, with ``read=False``: it is started all the same, and
    nothing in it was checked.
    """
    by_path = {f.relpath: f for f in index.files}
    if on_disk is None and not any(_real_suffix(rel) in DISGUISE_SUFFIXES for rel in by_path):
        return []
    runs: list[DisguisedRun] = []
    seen: set[tuple[str, str, int]] = set()

    def consider(text: str, near: str, source: str, where: Callable[[re.Match[str]], Evidence]):
        if not any(name in text for name in ("sh", "node", "python")):
            return
        for k, m in enumerate(_RUNS_FILE.finditer(text)):
            if k >= _MAX_MATCHES_PER_TEXT or len(runs) >= _MAX_RUNS:
                return
            word = m.group(3).strip("\"'")
            if posixpath.splitext(word.replace("\\", "/"))[1].lower() not in DISGUISE_SUFFIXES:
                continue
            family = _family(m.group(1))
            if _NOT_A_FILE_AFTER[family] & set(m.group(2).split()):
                continue
            for rel in _candidates(word, near):
                read = rel in by_path
                if not read and (on_disk is None or not on_disk(rel)):
                    continue
                evidence = where(m)
                key = (rel, evidence.file, evidence.line_start)
                if key not in seen:
                    seen.add(key)
                    runs.append(DisguisedRun(rel, _LANGUAGE[family], source, evidence, read))
                break

    for f in index.files:
        name = f.relpath.rsplit("/", 1)[-1]
        if name == "package.json":
            for _script, command, start, end in npm_install_commands(f, NPM_LIFECYCLE_SCRIPTS):
                consider(command, f.relpath, SOURCE_INSTALL,
                         lambda _m, f=f, start=start, end=end: f.evidence_for_span(start, end))
        elif f.relpath in index.install_scripts and _real_suffix(f.relpath) not in (
            DISGUISE_SUFFIXES
        ):
            consider(f.text, f.relpath, SOURCE_INSTALL, _in_file(f))
        elif _INSTRUCTION_FILE.search(f.relpath):
            consider(f.text, f.relpath, SOURCE_INSTRUCTION, _in_file(f))
    for command in autorun_commands(index).commands:
        if not command.is_http:
            consider(
                command.text, command.file.relpath, SOURCE_AUTORUN,
                lambda m, command=command: command.evidence(command.piece_at(m.start(3))),
            )
    return runs


def _in_file(f: IndexedFile) -> Callable[[re.Match[str]], Evidence]:
    return lambda m: f.evidence_for_span(m.start(), m.end())


class DisguisedScriptScanner(Scanner):
    name = "disguised_script"
    rules = [
        RuleSpec(
            id=R_DISGUISED,
            category="obfuscation",
            severity=Severity.HIGH,
            title="A command runs a script kept under an image, document or data file name",
            description=(
                "An npm install-time script, an agent instruction file or an auto-run command "
                "starts node, python or a shell on a file of this component whose name says it "
                "is an image, a document, a font, an archive or data (`node assets/logo.png`, "
                "`python3 assets/template.docx`). The interpreter runs it as code whatever it is "
                "called, while a reader of the file list sees no script. The file was read as "
                "the language it is started in, and what it does is reported by the other rules."
            ),
            recommendation=(
                "Read the named file as code before installing the component or letting an "
                "agent follow the instruction. A script an honest project runs carries a "
                "script's name."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        for run in disguised_runs(index):
            evidence.append(run.evidence)
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break
        if not evidence:
            return ScanResult()
        return ScanResult(findings=[_finding_from_rule(self.rules[0], evidence)])
