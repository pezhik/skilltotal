"""npm supply chain: dependencies from outside the registry, and install-time publishing.

A dependency given as a URL is fetched from that host when the package is installed. Its code is
not in the registry, so a scan of the package (or of the registry) never sees it, and the host
can serve something else at any time: the "remote dynamic dependency" that let the PhantomRaven
packages look empty. A git or GitHub dependency is the lesser form: the code is public, but not
pinned by the registry and not scanned with the package.

A self-spreading npm worm publishes from code npm runs at install time, with the token it finds
on the machine: it runs ``npm publish`` or PUTs a publish document (``_attachments`` with
``dist-tags``) to the registry. Release tools publish from a command the maintainer types,
never from an install script, so only the files npm runs at install count
(``FileIndex.install_scripts``) and the install commands in ``package.json`` themselves.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from skilltotal import bounded_json
from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import RuleSpec, Scanner, ScanResult, _finding_from_rule

R_URL_DEP = "ST-NPM-URL-DEP"
R_GIT_DEP = "ST-NPM-GIT-DEP"
R_INSTALL_PUBLISH = "ST-NPM-INSTALL-PUBLISH"

# The dependency lists a consumer's install fetches (devDependencies are not installed).
_INSTALLED_SECTIONS = ("dependencies", "optionalDependencies", "peerDependencies")
_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")
# Hosts whose archive URL is a git hosting's own snapshot of a repository.
_GIT_HOSTS = frozenset({"github.com", "codeload.github.com", "gitlab.com", "bitbucket.org"})
_GIT_SPEC = re.compile(
    r"^(?:git\+|git://|github:|gitlab:|bitbucket:|gist:)"
    r"|^[A-Za-z0-9_][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+(?:#\S*)?$"
)
_REGISTRY_TARBALL = re.compile(r"^https://registry\.(?:npmjs\.org|yarnpkg\.com)/")

_JS_SUFFIXES = (".js", ".cjs", ".mjs", ".ts", ".cts", ".mts")
_PUBLISH_CMD = r"(?:npm|pnpm|yarn|bun)(?:\.cmd)?\s+(?:npm\s+)?publish\b"
# `execSync("npm publish")`, a bundler's `(0,o.execSync)("npm publish")`, a template literal.
_JS_EXEC_PUBLISH = re.compile(
    r"\b(?:exec\w*|spawn\w*|execa\w*)\)?\s*\(\s*[`'\"]\s*" + _PUBLISH_CMD
)
# `spawn("npm", ["publish", ...])`.
_JS_SPAWN_PUBLISH = re.compile(
    r"\b(?:spawn\w*|execFile\w*|execa\w*)\)?\s*\(\s*[`'\"](?:npm|pnpm|yarn|bun)(?:\.cmd)?[`'\"]"
    r"\s*,\s*\[\s*(?:[`'\"]npm[`'\"]\s*,\s*)?[`'\"]publish[`'\"]"
)
# The document `npm publish` PUTs to the registry: the tarball under `_attachments`, the new
# version under `dist-tags`.
_ATTACHMENTS = re.compile(r"""(?<![\w$])['"]?_attachments['"]?\s*:""")
_DIST_TAGS = re.compile(r"""['"]dist-tags['"]\s*:""")
_PUBLISH_DOC_WINDOW = 2000
# A shell line (or a command after `&&`, `;`, `|`) that publishes.
_SHELL_PUBLISH = re.compile(r"(?:^|[;&|]\s*|\bthen\s+|\bdo\s+)\s*(?:[\w./-]*/)?" + _PUBLISH_CMD,
                            re.MULTILINE)


class NpmSupplyScanner(Scanner):
    name = "npm_supply"
    rules = [
        RuleSpec(
            id=R_URL_DEP,
            category="supply_chain",
            severity=Severity.HIGH,
            title="Dependency fetched from a URL outside the registry",
            description=(
                "package.json lists a dependency as an archive URL on a host of its own. npm "
                "fetches it from that host at install time: its code is not in the registry, is "
                "not part of this scan, and can change at any time without a new version."
            ),
            recommendation=(
                "Depend on a registry version instead. If the archive is yours, publish it; if "
                "it is not, find out what it contains before installing."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            names=("package.json",),
        ),
        RuleSpec(
            id=R_GIT_DEP,
            category="supply_chain",
            severity=Severity.LOW,
            title="Dependency fetched from a git repository",
            description=(
                "package.json lists a dependency as a git or GitHub source. npm clones it at "
                "install time: the code is not a registry release and is not part of this scan."
            ),
            recommendation=(
                "Prefer a registry release; otherwise pin the dependency to a commit hash."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            names=("package.json",),
        ),
        RuleSpec(
            id=R_INSTALL_PUBLISH,
            category="supply_chain",
            severity=Severity.CRITICAL,
            title="Install-time code publishes to the npm registry",
            description=(
                "Code that npm runs when this package is installed publishes a package: it runs "
                "`npm publish` or sends a publish document to the registry. Installing a package "
                "has no reason to publish one. With the npm token of the machine it is "
                "installed on, such code can publish new versions of every package that token "
                "can publish."
            ),
            recommendation=(
                "Do not install this version. If it was installed, revoke the npm tokens on that "
                "machine and check the versions recently published under them."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            code_context="comments",
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        url_deps: list[Evidence] = []
        git_deps: list[Evidence] = []
        publishes: list[Evidence] = []
        for f in index.files:
            if f.relpath.rsplit("/", 1)[-1] == "package.json":
                manifest = _manifest(f)
                if manifest is not None:
                    _dependencies(f, manifest, url_deps, git_deps)
                    publishes.extend(_install_commands_that_publish(f, manifest))
            if f.relpath in index.install_scripts:
                publishes.extend(_publishes(f))
        findings = [
            _finding_from_rule(rule, evidence)
            for rule, evidence in zip(self.rules, (url_deps, git_deps, publishes), strict=True)
            if evidence
        ]
        return ScanResult(findings=findings)


def _manifest(f: IndexedFile) -> dict | None:
    try:
        data = bounded_json.loads(f.text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _dependencies(f: IndexedFile, manifest: dict, url_deps: list[Evidence],
                  git_deps: list[Evidence]) -> None:
    for section in _INSTALLED_SECTIONS:
        deps = manifest.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if not isinstance(name, str) or not isinstance(spec, str):
                continue
            kind = _remote_kind(spec.strip())
            if kind is None:
                continue
            evidence = _entry_evidence(f, section, name, spec)
            if evidence is not None:
                (url_deps if kind == "url" else git_deps).append(evidence)


def _remote_kind(spec: str) -> str | None:
    """``url`` for an archive on a host of its own, ``git`` for a repository, else None."""
    if spec.startswith(("http://", "https://")):
        if _REGISTRY_TARBALL.match(spec):
            return None  # a registry release, by its tarball
        host = (urlparse(spec).hostname or "").lower()
        return "git" if host in _GIT_HOSTS else "url"
    if spec.startswith(("npm:", "file:", "link:", "workspace:", "portal:", "patch:", ".", "/",
                        "~")):
        return None
    return "git" if _GIT_SPEC.search(spec) else None


def _entry_evidence(f: IndexedFile, section: str, name: str, spec: str) -> Evidence | None:
    """The ``"name": "spec"`` line inside the ``section`` object (not a devDependencies copy)."""
    text = f.text
    key = re.search(r'"' + re.escape(section) + r'"\s*:\s*\{', text)
    if key is None:
        return None
    end = text.find("}", key.end())
    end = len(text) if end < 0 else end
    entry = re.compile(re.escape(json.dumps(name)) + r"\s*:\s*" + re.escape(json.dumps(spec)))
    m = entry.search(text, key.end(), end)
    if m is None:
        return f.evidence_for_span(key.start(), key.end())
    return f.evidence_for_span(m.start(), m.end())


def _install_commands_that_publish(f: IndexedFile, manifest: dict) -> list[Evidence]:
    scripts = manifest.get("scripts")
    if not isinstance(scripts, dict):
        return []
    found: list[Evidence] = []
    for script in _INSTALL_SCRIPTS:
        command = scripts.get(script)
        if not isinstance(command, str) or not re.search(_PUBLISH_CMD, command):
            continue
        m = re.search(r'"' + script + r'"\s*:\s*"', f.text)
        if m is not None:
            found.append(f.evidence_for_span(m.start(), m.end()))
    return found


def _publishes(f: IndexedFile) -> list[Evidence]:
    text = f.text
    found: list[Evidence] = []
    if f.suffix in _JS_SUFFIXES:
        for pattern in (_JS_EXEC_PUBLISH, _JS_SPAWN_PUBLISH):
            for m in pattern.finditer(text):
                found.append(f.evidence_for_span(m.start(), m.end()))
        for m in _ATTACHMENTS.finditer(text):
            window = text[max(0, m.start() - _PUBLISH_DOC_WINDOW):m.end() + _PUBLISH_DOC_WINDOW]
            if _DIST_TAGS.search(window):
                found.append(f.evidence_for_span(m.start(), m.end()))
                break
    else:
        for m in _SHELL_PUBLISH.finditer(text):
            found.append(f.evidence_for_span(m.start(), m.end()))
    return found
