"""Prebuilt artifacts the component runs but does not build from its own files.

A repository can be clean while what it starts is not: a compose file, a Kubernetes manifest, a
dev container or an MCP launch command that pulls a ready-made image, or an install script that
downloads a ready-made binary. The scan reads the repository, so the image or binary itself is never
checked (and is never pulled or run). In 2026 copycat forks of an open-source AI console kept the
source as it was and changed one compose line to pull a backdoored image from another publisher
(BadByte, "ARTEX backdoor docker image", 2026-11-04); one also shipped an installer that fetched a
binary built from uncommitted code over plain HTTP.

Four rules, each anchored to the line that names the artifact:

* ``ST-ARTIFACT-FOREIGN-IMAGE`` - an image that carries the project's own name, published under a
  namespace that is none of the project's own (its module path, manifest repository URLs, README
  clone line, npm scope, or an image the repository itself builds and pushes). Silent when the
  repository declares no identity at all: then there is nothing to compare against.
* ``ST-ARTIFACT-HTTP-BINARY`` - a script that downloads an executable or archive over plain
  ``http://`` from a public host: anyone on the path can swap it.
* ``ST-ARTIFACT-DIRTY-BUILD`` - a fetched binary or image tagged ``-dirty``: built from changes
  that were never committed, so no published source matches it.
* ``ST-ARTIFACT-KNOWN-BAD`` - an image named in a public report as trojanized.

``prebuilt_artifacts`` lists the images the component runs without building them, for the
verdict, which names them instead of implying they were checked.

Detection patterns below are string literals; nothing here pulls, downloads or runs anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from skilltotal import bounded_json
from skilltotal.autorun import KIND_MCP_SERVER, autorun_commands
from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
)
from skilltotal.scanners.mcp_pinning import _DOCKER_VALUE_FLAGS

R_FOREIGN_IMAGE = "ST-ARTIFACT-FOREIGN-IMAGE"
R_HTTP_BINARY = "ST-ARTIFACT-HTTP-BINARY"
R_DIRTY_BUILD = "ST-ARTIFACT-DIRTY-BUILD"
R_KNOWN_BAD = "ST-ARTIFACT-KNOWN-BAD"

# Images a public report names as trojanized: namespace/name (Docker Hub, no tag) -> source.
# Exact names only; the threat-intel build adds to this list.
KNOWN_TROJANIZED_IMAGES: dict[str, str] = {
    "tomicdd/artex": "BadByte, ARTEX backdoor docker image, 2026-11-04",
    "congdonglinux/artex": "BadByte, ARTEX backdoor docker image, 2026-11-04",
}

# Where an image the component runs is named.
_COMPOSE_RE = re.compile(r"(?:^|/)(?:docker-)?compose(?:[.-][^/]*)?\.ya?ml$", re.IGNORECASE)
_MANIFEST_DIR_RE = re.compile(
    r"(?:^|/)(?:k8s|kubernetes|manifests|deploy|deployment|helm|charts)/[^\n]*\.ya?ml$",
    re.IGNORECASE,
)
_DEVCONTAINER_RE = re.compile(r"(?:^|/)\.?devcontainer(?:/[^/]*)?\.json$", re.IGNORECASE)
_DOCKERFILE_RE = re.compile(r"(?:^|/)(?:[^/]*\.)?(?:Dockerfile|Containerfile)(?:\.[^/]*)?$",
                            re.IGNORECASE)
_IMAGE_LINE = re.compile(r"^([ \t]*)(?:-[ \t]*)?[\"']?image[\"']?[ \t]*:[ \t]*[\"']?"
                         r"([^\s\"'#,]+)", re.MULTILINE)
_FROM_LINE = re.compile(r"^[ \t]*FROM[ \t]+(?:--platform=\S+[ \t]+)?(\S+)(?:[ \t]+AS[ \t]+(\S+))?",
                        re.MULTILINE | re.IGNORECASE)

# Who the project says it is.
_GITHUB_REPO = re.compile(
    r"github\.com[/:]([A-Za-z0-9][A-Za-z0-9-]*)/([A-Za-z0-9._-]+?)(?:\.git)?(?=[/\s\"')#?,]|\.?$)",
    re.MULTILINE,
)
_GO_MODULE = re.compile(r"^module[ \t]+github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)",
                        re.MULTILINE)
_TOML_NAME = re.compile(r"^name[ \t]*=[ \t]*[\"']([^\"']+)[\"']", re.MULTILINE)
_MANIFEST_NAMES = frozenset({"package.json", "pyproject.toml", "setup.py", "setup.cfg",
                             "cargo.toml", "go.mod"})
# An image the repository itself builds and publishes (CI, scripts, Makefile).
_BUILT_IMAGE = re.compile(
    r"(?:docker[ \t]+(?:buildx[ \t]+)?build\b[^\n]*?[ \t](?:-t|--tag)[ \t=]+"
    r"|docker[ \t]+push[ \t]+|docker[ \t]+tag[ \t]+\S+[ \t]+"
    r"|\bimages?[ \t]*:[ \t]*[|>]?[ \t]*(?:\n[ \t]*)?"
    r"|\bIMAGE(?:_NAME|_NAMESPACE|_REPO(?:SITORY)?)?[ \t]*[:=][ \t]*"
    r"|\btags[ \t]*:[ \t]*[|>]?[ \t]*(?:\n[ \t]*)?)"
    r"[\"']?([A-Za-z0-9][\w.:/${}-]*/[\w.${}-]+)",
    re.IGNORECASE,
)

# Downloads in scripts.
_DOWNLOAD_SURFACE = re.compile(
    r"(?:\.(?:sh|bash|zsh|ps1|psm1|bat|cmd)$|(?:^|/)(?:[^/]*\.)?(?:Dockerfile|Containerfile)"
    r"(?:\.[^/]*)?$|(?:^|/)(?:GNU)?makefile$)",
    re.IGNORECASE,
)
_DOWNLOADER = re.compile(
    r"\b(?:curl|wget|aria2c|Invoke-WebRequest|iwr|Start-BitsTransfer|DownloadFile|"
    r"certutil)\b",
    re.IGNORECASE,
)
_ARTIFACT_SUFFIX = (r"\.(?:zip|tar|tgz|tbz2?|txz|gz|xz|bz2|7z|rar|exe|msi|dll|bin|run|deb|rpm|"
                    r"apk|appimage|dmg|pkg|jar|whl|so)")
_PRIVATE_HOST = (r"(?:localhost|127\.|0\.0\.0\.0|\[|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|"
                 r"host\.docker\.internal|[^/\s\"']*\.(?:local|localhost)(?=[:/])"
                 r"|(?:[^/\s\"']*\.)?example\.(?:com|org|net)(?=[:/]))")
_HTTP_ARTIFACT = re.compile(
    r"\bhttp://(?!" + _PRIVATE_HOST + r")[^\s\"'`)<>{}]{1,500}?" + _ARTIFACT_SUFFIX
    + r"(?=[\s\"'`)<>?#;|}]|$)",
    re.IGNORECASE,
)
_DIRTY_ARTIFACT = re.compile(
    r"[\w.+-]*[-+.]dirty(?:[-+.][\w.+-]*)?" + _ARTIFACT_SUFFIX + r"(?![\w])",
    re.IGNORECASE,
)
_DIRTY_TAG = re.compile(r"[-+.]dirty(?:$|[-+.])", re.IGNORECASE)


@dataclass(frozen=True)
class ImageRef:
    """An image a file of the component names, and where."""

    text: str  # as written, tag included
    registry: str  # "" for Docker Hub
    namespace: str  # "" for an official library image
    name: str
    tag: str
    file: IndexedFile
    start: int
    end: int
    built_here: bool  # the same file builds it (a compose service with `build:`)

    @property
    def repo(self) -> str:
        """namespace/name on Docker Hub, registry/namespace/name elsewhere (no tag)."""
        path = f"{self.namespace}/{self.name}" if self.namespace else self.name
        return f"{self.registry}/{path}" if self.registry else path


def _norm(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def parse_image(text: str) -> tuple[str, str, str, str] | None:
    """(registry, namespace, name, tag) of an image reference, or None for a template, a local
    build stage or anything that is not an image name."""
    ref = text.strip().strip("\"'")
    ref = ref.split("@", 1)[0]
    if not ref or ref.startswith(("$", "{", "<", ".", "/")):
        return None
    last = ref.rsplit("/", 1)[-1]
    tag = ""
    if ":" in last:
        last, tag = last.split(":", 1)
        ref = ref[: ref.rfind("/") + 1] + last if "/" in ref else last
    if "$" in ref or "{" in ref or not re.fullmatch(r"[A-Za-z0-9][\w./:-]*", ref):
        return None
    parts = ref.split("/")
    registry = ""
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry = parts.pop(0).lower()
    if registry in ("docker.io", "index.docker.io", "registry-1.docker.io"):
        registry = ""
    if not registry and parts[:1] == ["library"]:
        parts = parts[1:]
    if not parts or not all(parts):
        return None
    namespace = "/".join(parts[:-1])
    return registry, namespace.lower(), parts[-1].lower(), tag


_BUILD_KEY = re.compile(r"[\"']?build[\"']?[ \t]*:")


def _compose_service_builds(text: str, image_line_start: int, indent: str) -> bool:
    """True when the compose service holding this `image:` line also has a `build:` key: the
    image is then the tag of a build from the repository, not something pulled."""
    lines = text.split("\n")
    row = text.count("\n", 0, image_line_start)
    width = len(indent.expandtabs())
    for step in (-1, 1):
        j = row + step
        while 0 <= j < len(lines):
            line = lines[j].expandtabs()
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                own = len(line) - len(line.lstrip())
                if own < width:
                    break  # left the service block
                if own == width and _BUILD_KEY.match(stripped):
                    return True
            j += step
    return False


def _commented(f: IndexedFile, offset: int) -> bool:
    """A match in a `#` comment of a script, Dockerfile or Makefile documents, it does not run."""
    if f.in_shell_comment(offset):
        return True
    line_start = f.text.rfind("\n", 0, offset) + 1
    return f.text[line_start:offset].lstrip().startswith(("#", "REM ", "rem ", "::"))


def image_refs(index: FileIndex) -> list[ImageRef]:
    """Every image a compose file, Kubernetes/Helm manifest, dev container, Dockerfile or MCP
    launch command of the component names."""
    refs: list[ImageRef] = []

    def add(raw: str, f: IndexedFile, start: int, end: int, built_here: bool = False) -> None:
        parsed = parse_image(raw)
        if parsed is None:
            return
        registry, namespace, name, tag = parsed
        refs.append(ImageRef(raw, registry, namespace, name, tag, f, start, end, built_here))

    for f in index.files:
        rel = f.relpath
        compose = _COMPOSE_RE.search(rel) is not None
        if compose or _MANIFEST_DIR_RE.search(rel) or _DEVCONTAINER_RE.search(rel):
            for m in _IMAGE_LINE.finditer(f.text):
                built = compose and _compose_service_builds(f.text, m.start(), m.group(1))
                add(m.group(2), f, m.start(2), m.end(2), built)
        elif _DOCKERFILE_RE.search(rel):
            stages: set[str] = set()
            for m in _FROM_LINE.finditer(f.text):
                if m.group(1).lower() not in stages:
                    add(m.group(1), f, m.start(1), m.end(1))
                if m.group(2):
                    stages.add(m.group(2).lower())
    for command in autorun_commands(index).commands:
        if command.kind != KIND_MCP_SERVER or not command.pieces:
            continue
        piece = _docker_run_image(command.pieces)
        if piece is not None:
            add(piece.text, command.file, piece.start, piece.end)
    return refs


def _docker_run_image(pieces):
    """The image argument of a `docker run` / `podman run` launch command, or None."""
    program = pieces[0].text.replace("\\", "/").rsplit("/", 1)[-1].lower()
    program = re.sub(r"\.(?:cmd|exe)$", "", program)
    if program not in ("docker", "podman") or len(pieces) < 2 or pieces[1].text != "run":
        return None
    i = 2
    while i < len(pieces):
        arg = pieces[i].text
        if arg.startswith("-"):
            i += 2 if arg in _DOCKER_VALUE_FLAGS and "=" not in arg else 1
            continue
        return pieces[i]
    return None


@dataclass
class _Identity:
    owners: set[str]  # normalized namespaces / owners the project names as its own
    names: set[str]  # normalized project names
    built: set[tuple[str, str]]  # (normalized namespace, normalized name) the repo publishes


def project_identity(index: FileIndex) -> _Identity:
    """Who the component says it is, from its own manifests, README clone line and build files."""
    ident = _Identity(set(), set(), set())

    def own_repo(owner: str, repo: str) -> None:
        ident.owners.add(_norm(owner))
        ident.names.add(_norm(repo))

    for f in index.files:
        base = f.relpath.rsplit("/", 1)[-1].lower()
        if base in _MANIFEST_NAMES:
            if base == "go.mod":
                for owner, repo in _GO_MODULE.findall(f.text):
                    own_repo(owner, repo)
                continue
            for owner, repo in _GITHUB_REPO.findall(f.text[:200_000]):
                own_repo(owner, repo)
            if base == "package.json":
                try:
                    data = bounded_json.loads(f.text)
                except ValueError:
                    data = None
                name = data.get("name", "") if isinstance(data, dict) else ""
                if isinstance(name, str) and name:
                    if name.startswith("@") and "/" in name:
                        ident.owners.add(_norm(name[1:].split("/", 1)[0]))
                    ident.names.add(_norm(name.rsplit("/", 1)[-1]))
            elif base in ("pyproject.toml", "cargo.toml"):
                for name in _TOML_NAME.findall(f.text)[:2]:
                    ident.names.add(_norm(name))
        elif base.startswith("readme"):
            # Only how the README tells people to get this project: its clone line.
            for line in f.text.splitlines():
                if "git clone" in line:
                    for owner, repo in _GITHUB_REPO.findall(line):
                        own_repo(owner, repo)
        if (f.relpath.startswith(".github/workflows/") or base.endswith((".sh", ".ps1"))
                or base in ("makefile", "justfile") or "dockerfile" in base):
            for m in _BUILT_IMAGE.finditer(f.text):
                parsed = parse_image(m.group(1))
                if parsed is not None and parsed[1]:
                    ns = _norm(parsed[1].rsplit("/", 1)[-1])
                    ident.built.add((ns, _norm(parsed[2])))
                    ident.owners.add(ns)
    ident.names.discard("")
    ident.owners.discard("")
    return ident


# Names too generic to identify a project: a monorepo package called `server` or `web` says nothing
# about whose `mcr.microsoft.com/mssql/server` image is.
_GENERIC_NAMES = frozenset({
    "app", "api", "web", "www", "site", "server", "client", "frontend", "backend", "worker",
    "core", "cli", "ui", "mcp", "mcpserver", "base", "runtime", "proxy", "gateway", "db",
    "database", "service", "services", "docs", "demo", "example", "examples", "test", "tests",
    "main", "agent", "bot", "node", "python", "dev", "build", "docker", "image", "plugin",
})


def _project_name(name: str, ident: _Identity) -> bool:
    n = _norm(name)
    return len(n) >= 3 and n not in _GENERIC_NAMES and n in ident.names


def _owned(namespace: str, owners: set[str]) -> bool:
    ns = _norm(namespace.rsplit("/", 1)[-1])
    return any(ns == o or (min(len(ns), len(o)) >= 4 and (ns in o or o in ns)) for o in owners)


def foreign_images(refs: list[ImageRef], ident: _Identity) -> list[ImageRef]:
    """Images with the project's own name from a namespace that is none of the project's own."""
    if not ident.owners or not ident.names:
        return []
    out = []
    for ref in refs:
        if not ref.namespace or ref.built_here or not _project_name(ref.name, ident):
            continue
        if _owned(ref.namespace, ident.owners):
            continue
        if (_norm(ref.namespace.rsplit("/", 1)[-1]), _norm(ref.name)) in ident.built:
            continue
        out.append(ref)
    return out


def prebuilt_artifacts(index: FileIndex) -> list[dict]:
    """The images the component runs that its files do not build, for the verdict: Docker
    official images (no namespace) are left out, as is any image a compose service builds
    from the repository or the repository's own build publishes."""
    ident = project_identity(index)
    seen: set[str] = set()
    out: list[dict] = []
    for ref in image_refs(index):
        if not ref.namespace or ref.built_here:
            continue
        if (_norm(ref.namespace.rsplit("/", 1)[-1]), _norm(ref.name)) in ident.built:
            continue
        if ref.repo in seen:
            continue
        seen.add(ref.repo)
        out.append({
            "kind": "image",
            "ref": ref.repo,
            "file": ref.file.relpath,
            "own_name": _project_name(ref.name, ident),
        })
    return out


_FOREIGN_IMAGE_RULE = RuleSpec(
    id=R_FOREIGN_IMAGE,
    category="supply_chain",
    severity=Severity.HIGH,
    title="Runs a prebuilt image of this project from another publisher",
    description=(
        "A compose file, manifest or launch command runs a ready-made image with this "
        "project's name, published under a namespace the project does not claim (its module "
        "path, repository URLs, clone instructions or the images its build publishes). The "
        "image is not built from these files, and its contents were not checked."
    ),
    recommendation=(
        "Build the image from this source, or pull it from the project's own publisher. Check "
        "who publishes the image before running it."
    ),
    capability=None,
    threat_class=ThreatClass.RISKY_CONSTRUCT,
)

_HTTP_BINARY_RULE = RuleSpec(
    id=R_HTTP_BINARY,
    category="supply_chain",
    severity=Severity.MEDIUM,
    title="Downloads an executable or archive over plain HTTP",
    description=(
        "A script downloads an executable, package or archive from a public host over plain "
        "http://, without TLS. Anyone on the network path can replace the file, and the scan "
        "does not check it."
    ),
    recommendation=(
        "Download over HTTPS from the project's own release page and verify a published "
        "checksum or signature before running it."
    ),
    capability=None,
    threat_class=ThreatClass.RISKY_CONSTRUCT,
)

_DIRTY_BUILD_RULE = RuleSpec(
    id=R_DIRTY_BUILD,
    category="supply_chain",
    severity=Severity.MEDIUM,
    title="Fetches a build made from uncommitted code",
    description=(
        "A downloaded binary or an image is tagged 'dirty', which marks a build made from "
        "changes that were never committed. No published source matches what runs."
    ),
    recommendation=(
        "Use a release built from a tagged commit, or build from the source you reviewed."
    ),
    capability=None,
    threat_class=ThreatClass.RISKY_CONSTRUCT,
)

_KNOWN_BAD_RULE = RuleSpec(
    id=R_KNOWN_BAD,
    category="supply_chain",
    severity=Severity.CRITICAL,
    title="Runs an image that a public report names as trojanized",
    description=(
        "The component runs a container image that a published security report names as "
        "trojanized."
    ),
    recommendation=(
        "Do not run this image. Remove containers started from it and rebuild from source; "
        "treat data and credentials the container could reach as exposed."
    ),
    capability=None,
    threat_class=ThreatClass.MALICIOUS_INDICATOR,
)


class ArtifactProvenanceScanner(Scanner):
    name = "artifact_provenance"
    rules = [_FOREIGN_IMAGE_RULE, _HTTP_BINARY_RULE, _DIRTY_BUILD_RULE, _KNOWN_BAD_RULE]

    def scan(self, index: FileIndex) -> ScanResult:
        refs = image_refs(index)
        found: dict[str, list[Evidence]] = {r.id: [] for r in self.rules}

        def note(rule_id: str, f: IndexedFile, start: int, end: int) -> None:
            if len(found[rule_id]) < MAX_EVIDENCE_SCANNED:
                found[rule_id].append(f.evidence_for_span(start, end))

        for ref in refs:
            if ref.repo in KNOWN_TROJANIZED_IMAGES:
                note(R_KNOWN_BAD, ref.file, ref.start, ref.end)
            if ref.tag and _DIRTY_TAG.search(ref.tag):
                note(R_DIRTY_BUILD, ref.file, ref.start, ref.end)
        if refs:
            for ref in foreign_images(refs, project_identity(index)):
                note(R_FOREIGN_IMAGE, ref.file, ref.start, ref.end)

        for f in index.files:
            if not _DOWNLOAD_SURFACE.search(f.relpath) or not _DOWNLOADER.search(f.text):
                continue
            if "http://" in f.text:
                for m in _HTTP_ARTIFACT.finditer(f.text):
                    if not _commented(f, m.start()):
                        note(R_HTTP_BINARY, f, m.start(), m.end())
            if "dirty" in f.text.lower():
                for m in _DIRTY_ARTIFACT.finditer(f.text):
                    if not _commented(f, m.start()):
                        note(R_DIRTY_BUILD, f, m.start(), m.end())

        findings = [_finding_from_rule(rule, found[rule.id]) for rule in self.rules
                    if found[rule.id]]
        return ScanResult(findings=findings)
