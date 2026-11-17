"""A dependency, or a package a launch command runs, whose name imitates a popular package.

``ST-TYPOSQUAT`` judges the name of the package being scanned. The same trick works one step
further out: a component whose own name is unremarkable depends on ``axois`` or ``requ3sts``, its
MCP configuration starts ``uvx mcp-server-fetchh`` or ``npx @modelcontextprotocoI/server-github``,
or its instructions tell the agent to ``pip install`` such a name. The code that arrives belongs
to whoever registered the look-alike, and none of it is in the scanned files.

``ST-DEP-TYPOSQUAT`` (risky construct) reads the names from:

* ``package.json``: ``dependencies``, ``devDependencies``, ``optionalDependencies`` and
  ``peerDependencies`` whose value is a registry version (an alias, a path, a URL or a repository
  is a different source and is not a registry name);
* ``requirements*.txt`` / ``constraints*.txt`` and the ``dependencies`` / ``requires`` arrays of
  ``pyproject.toml``;
* the launch command of an MCP server (``skilltotal.autorun``: npx / bunx / ``pnpm dlx``, uvx /
  ``uv tool run`` / ``pipx run``);
* ``pip install`` / ``npm install`` / ``npx`` / ``uvx`` commands in an instruction file
  (``SKILL.md``, a command or agent file, ``CLAUDE.md`` ...).

Which names count is decided by ``typosquatting.name_lookalike``: only the ways a name is mistyped
or disguised, never plain closeness, because honest packages sit one letter from popular ones.
Lockfiles are not read: they list every transitive name. Nothing is looked up or installed.
"""

from __future__ import annotations

import re
from itertools import islice

from skilltotal import bounded_json
from skilltotal.autorun import KIND_MCP_SERVER, autorun_commands
from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Evidence, Finding, Severity, ThreatClass
from skilltotal.scanners.base import MAX_EVIDENCE_SCANNED, RuleSpec, Scanner, ScanResult
from skilltotal.scanners.mcp_pinning import launched_packages
from skilltotal.scanners.skill_fetch_exec import _INSTRUCTION_FILE
from skilltotal.typosquatting import name_lookalike

RULE_ID = "ST-DEP-TYPOSQUAT"

_NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
# A registry version or range. Anything with a scheme, a path or a slash comes from elsewhere.
_NOT_REGISTRY_VERSION = re.compile(r"[:/]|^\s*(?:\.|~/)")
_MAX_MANIFESTS = 50
_MAX_NAMES = 2000
_REQUIREMENTS_FILE = re.compile(r"^(?:requirements|constraints)[\w.-]*\.(?:txt|in)$", re.IGNORECASE)
# The name at the start of a requirement line or specifier; whatever follows it (a version, an
# extra, a marker) is not part of the name.
_REQUIREMENT_NAME = re.compile(r"[ \t]*([^\s=<>!~;,\[\]()#@'\"/\\:]{1,80})")
_SKIPPED_REQUIREMENT = re.compile(r"[ \t]*(?:#|-|$|\.|/|[A-Za-z][\w+.-]*://|git\+)")
_TOML_ARRAY = re.compile(r"(?m)^[ \t]*(?:dependencies|requires)[ \t]*=[ \t]*\[")
_TOML_STRING = re.compile(r"""(["'])([^"'\n]{1,300})\1""")
_MAX_TOML_ARRAY = 20_000
# Install and run commands in an instruction file. Group 1 is the Python tool, group 2 the npm
# one; group 3 is the rest of the command up to the end of the statement.
_INSTALL_COMMAND = re.compile(
    r"(?<![\w./-])(?:((?:pip3?|python3?[ \t]+-m[ \t]+pip|uv[ \t]+pip|pipx)[ \t]+install|uvx)"
    r"|(npm[ \t]+(?:install|i|add)|yarn[ \t]+(?:global[ \t]+)?add|pnpm[ \t]+add|bun[ \t]+add|"
    r"npx|bunx))[ \t]+([^\n;&|`)#]{1,300})"
)
_INSTALL_VALUE_FLAGS = frozenset({
    "-r", "--requirement", "-e", "--editable", "-c", "--constraint", "-i", "--index-url",
    "--extra-index-url", "-t", "--target", "--prefix", "--registry", "--python", "--from",
    "--with", "-p", "--package", "--cache", "-w", "--workspace", "--tag",
})
_MAX_COMMANDS = 200
_SPEC_NAME_NPM = re.compile(r"^(@[^/@\s]+/[^@\s/]+|[^@\s/]+)(?:@.*)?$")


def _npm_name(spec: str) -> str | None:
    m = _SPEC_NAME_NPM.match(spec.strip("\"'"))
    return m.group(1) if m else None


def _py_name(spec: str) -> str | None:
    spec = spec.strip("\"'")
    if _SKIPPED_REQUIREMENT.match(spec):
        return None
    m = _REQUIREMENT_NAME.match(spec)
    return m.group(1) if m else None


class DependencyTyposquatScanner(Scanner):
    name = "dependency_typosquat"
    rules = [
        RuleSpec(
            id=RULE_ID,
            category="supply_chain",
            severity=Severity.HIGH,
            title="Dependency or launched package name imitates a popular package",
            description=(
                "A package the component depends on (package.json, requirements.txt, "
                "pyproject.toml), starts as an MCP server (npx, uvx) or tells the agent to "
                "install is named like a widely-used package and is not that package: two "
                "letters swapped, a doubled letter added or dropped, a letter left out of a "
                "long name, digits or look-alike characters in place of letters, other "
                "separators, or a scope one character from a well-known one. Installing the "
                "component installs that other package, whose code is not part of this scan. "
                "This flags the resemblance only."
            ),
            recommendation=(
                "Check the name against the package you expect. If it is a typo, the look-alike "
                "may already be registered by someone else: fix the name before installing. If "
                "it is a real package you chose, accept the finding."
            ),
            capability=None,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        hits: list[tuple[Evidence, str, str, str]] = []  # evidence, name, popular, how
        seen: set[tuple[str, str]] = set()

        def check(f: IndexedFile, name: str | None, eco: str, start: int, end: int) -> None:
            if not name or len(hits) >= MAX_EVIDENCE_SCANNED or (eco, name) in seen:
                return
            seen.add((eco, name))
            found = name_lookalike(name, eco)
            if found:
                hits.append((f.evidence_for_span(start, end), name, *found))

        for f in islice(index.select(names=("package.json",)), _MAX_MANIFESTS):
            _package_json(f, check)
        for f in index.files:
            lower = f.name.lower()
            if _REQUIREMENTS_FILE.match(lower):
                _requirements(f, check)
            elif lower == "pyproject.toml":
                _pyproject(f, check)
            elif _INSTRUCTION_FILE.search(f.relpath):
                _instruction_commands(f, check)
        for command in autorun_commands(index).commands:
            if command.kind != KIND_MCP_SERVER or not command.pieces:
                continue
            eco, specs = launched_packages([p.text for p in command.pieces])
            for piece in command.pieces[1:]:
                if piece.text in specs:
                    name = _npm_name(piece.text) if eco == "npm" else _py_name(piece.text)
                    check(command.file, name, eco, piece.start, max(piece.start + 1, piece.end))
        if not hits:
            return ScanResult()
        rule = self.rules[0]
        shown = "; ".join(
            f"'{name}' reads as '{popular}' ({how})" for _ev, name, popular, how in hits[:6]
        )
        more = f"; and {len(hits) - 6} more" if len(hits) > 6 else ""
        return ScanResult(findings=[Finding(
            id=rule.id, severity=rule.severity, category=rule.category, title=rule.title,
            description=f"{rule.description} Found: {shown}{more}.",
            evidence=[ev for ev, *_ in hits],
            recommendation=rule.recommendation,
            threat_class=rule.threat_class,
        )])


def _package_json(f: IndexedFile, check) -> None:
    if '"' not in f.text:
        return
    try:
        data = bounded_json.loads(f.text)
    except ValueError:
        return
    if not isinstance(data, dict):
        return
    at = 0
    for section in _NPM_SECTIONS:
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for name, version in islice(deps.items(), _MAX_NAMES):
            if not isinstance(name, str) or not isinstance(version, str):
                continue
            if _NOT_REGISTRY_VERSION.search(version):
                continue
            # The key as written (a non-ASCII name may be escaped: then anchor the section).
            key = f.text.find('"' + name + '"', at)
            if key < 0:
                key = f.text.find('"' + name + '"')
            if key < 0:
                key = f.text.find('"' + section + '"')
                if key >= 0:
                    check(f, name, "npm", key + 1, key + 1 + len(section))
                continue
            at = key
            check(f, name, "npm", key + 1, key + 1 + len(name))


def _requirements(f: IndexedFile, check) -> None:
    offset = 0
    for line in islice(f.text.splitlines(keepends=True), _MAX_NAMES):
        if not _SKIPPED_REQUIREMENT.match(line):
            m = _REQUIREMENT_NAME.match(line)
            if m:
                check(f, m.group(1), "pypi", offset + m.start(1), offset + m.end(1))
        offset += len(line)


def _pyproject(f: IndexedFile, check) -> None:
    for array in islice(_TOML_ARRAY.finditer(f.text), _MAX_MANIFESTS):
        end = f.text.find("]", array.end(), array.end() + _MAX_TOML_ARRAY)
        if end < 0:
            continue
        for m in islice(_TOML_STRING.finditer(f.text, array.end(), end), _MAX_NAMES):
            name = _py_name(m.group(2))
            if name:
                check(f, name, "pypi", m.start(2), m.start(2) + len(name))


def _instruction_commands(f: IndexedFile, check) -> None:
    if "install" not in f.text and "npx" not in f.text and "uvx" not in f.text \
            and " add " not in f.text:
        return
    for m in islice(_INSTALL_COMMAND.finditer(f.text), _MAX_COMMANDS):
        eco = "pypi" if m.group(1) else "npm"
        runs_one = (m.group(1) or m.group(2)) in ("uvx", "npx", "bunx")
        words = list(re.finditer(r"\S+", m.group(3)))
        skip = False
        for word in words:
            text = word.group(0)
            if skip:
                skip = False
                continue
            if text.startswith("-"):
                skip = text in _INSTALL_VALUE_FLAGS
                continue
            name = _npm_name(text) if eco == "npm" else _py_name(text)
            start = m.start(3) + word.start()
            check(f, name, eco, start, start + len(text))
            if runs_one:
                break  # the words after the package are its own arguments
