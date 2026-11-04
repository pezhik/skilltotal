"""Install-time payload shapes that the generic install-hook checks do not name.

Each rule here needs the install context (a lifecycle script of ``package.json`` or a script it
starts with ``npm run``, a file one of them runs, ``setup.py``, or the modules of an in-tree PEP 517
build backend) AND a second tell that an honest install step does not have:

* a registry address decoded at run time and handed to a second ``npm install``;
* a DNS lookup whose name carries the machine's host name;
* a shell interpreter started on a ``.js`` file (JavaScript syntax hides shell substitutions);
* a user-level service or launch agent written next to a token-validity check;
* a build script that downloads a file and then starts that same file.

Detection patterns below are string literals; nothing here runs a command.
"""

from __future__ import annotations

import posixpath
import re

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.loaded_code import _module_paths, _python_targets
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import RuleSpec, Scanner, ScanResult, _finding_from_rule
from skilltotal.scanners.install_scripts import install_run_interpreters, npm_install_commands

CATEGORY = "install_time_execution"
R_MASKED_REGISTRY = "ST-INSTALL-NPM-MASKED-REGISTRY"
R_DNS_BEACON = "ST-INSTALL-NPM-DNS-BEACON"
R_SHELL_RUNS_JS = "ST-INSTALL-NPM-SHELL-RUNS-JS"
R_SERVICE_TOKEN_WATCH = "ST-INSTALL-NPM-SERVICE-TOKEN-WATCH"  # nosec B105 - rule id
R_PY_DOWNLOAD_EXEC = "ST-INSTALL-PY-DOWNLOAD-EXEC"

_LIFECYCLE = ("preinstall", "install", "postinstall")

# `npm install <pkg> --registry " + value` / `--registry ${value}`: the address is not written out.
_REGISTRY_FROM_VALUE = re.compile(
    r"\bnpm\s{1,4}(?:install|i|add)\b[^\n]{0,160}?--registry[= ]?[\"'`]?\s{0,3}(?:\+|\$\{)"
)
_DECODES_ADDRESS = re.compile(r"\bbase64\b|\batob\s*\(|\bfromCharCode\b")

_DNS_WITH_HOSTNAME = re.compile(
    r"(?:\bdns\b|\bresolver\b)[^\n]{0,60}?(?:lookup|resolve\w{0,8})\([^\n]{0,200}?\bhostname\s*\(\)"
)

# `sh ./prepare.js`, `bash -e setup.cjs`: a shell reads a file named like JavaScript.
_SHELL_ON_JS = re.compile(
    r"(?<![\w/.-])(?:sh|bash|zsh|dash)\s{1,4}(?:-[a-z]{1,2}\s{1,4}){0,2}[\"']?[\w./@-]{1,100}"
    r"\.(?:c|m)?js\b"
)

_USER_SERVICE = re.compile(
    r"\.config[/\\\"', ]{1,8}systemd[/\\\"', ]{1,8}user\b|Library[/\\\"', ]{1,8}LaunchAgents\b"
)
_TOKEN_REVOKED = re.compile(r"\b401\b|\brevoked\b|\bBad credentials\b", re.IGNORECASE)
_TOKEN_WORD = re.compile(r"\btoken\b|\bAuthorization\b", re.IGNORECASE)

_PY_DOWNLOAD = re.compile(
    r"\burlretrieve\(\s{0,3}[^,\n]{1,200},\s{0,3}"
    r"(?:([\"'])([^\"'\n]{1,120})\1|([A-Za-z_]\w{0,40}))\s{0,3}\)"
)
_PY_EXEC_CALL = r"(?:Popen|run|call|check_call|check_output|system|execv\w{0,2}|spawn\w{0,2})"
_INTERPRETER_ARG = r"(?:[\"'](?:sudo|sh|bash|python3?|node)[\"'],\s{0,3})?"


# A response fetched into a name (`r = requests.get(u)`, `resp = urlopen(u)`, httpx, a urllib3
# pool), or opened with `with urlopen(u) as r:`.
_PY_FETCH_INTO = re.compile(
    r"\b([A-Za-z_]\w{0,40})\s{0,3}=\s{0,3}(?:(?:requests|httpx|session|client)\.(?:get|post|request)"
    r"|(?:urllib\.request\.|request\.)?urlopen|[\w.]{0,60}PoolManager\(\s{0,3}\)\.request)\s{0,3}\("
    r"|\bwith\s{1,3}(?:urllib\.request\.)?urlopen\([^\n]{0,300}?\)\s{1,3}as\s{1,3}([A-Za-z_]\w{0,40})"
)
# A file opened for writing (`open(path, "wb")`) or written whole (`Path(path).write_bytes(`).
_PY_WRITE_TARGET = r"(?:([\"'])([^\"'\n]{1,120})\1|([A-Za-z_]\w{0,40}))"
_PY_OPEN_WRITE = re.compile(
    rf"\bopen\(\s{{0,3}}{_PY_WRITE_TARGET}\s{{0,3}},\s{{0,3}}[\"'][wax]b?\+?[\"']"
    rf"|\bPath\(\s{{0,3}}{_PY_WRITE_TARGET}\s{{0,3}}\)\.write_(?:bytes|text)\("
)
_PY_WRITE_REACH = 400


def _py_downloads(f: IndexedFile) -> list[tuple[int, int, str | None, str | None]]:
    """``(start, end, literal path, path variable)`` of each file a Python script downloads: an
    ``urlretrieve`` target, or a file the script writes a fetched response into (the response's
    own name is written within a few lines of the ``open``)."""
    text = f.text
    out = [(m.start(), m.end(), m.group(2), m.group(3)) for m in _PY_DOWNLOAD.finditer(text)]
    fetched = [(m.group(1) or m.group(2), m.end()) for m in _PY_FETCH_INTO.finditer(text)]
    if not fetched:
        return out
    for w in _PY_OPEN_WRITE.finditer(text):
        literal = w.group(2) or w.group(5)
        name = w.group(3) or w.group(6)
        window = text[w.start():w.end() + _PY_WRITE_REACH]
        for response, after in fetched:
            if after > w.start():
                continue
            r = re.escape(response)
            if re.search(rf"(?:\.write(?:_bytes|_text)?|copyfileobj)\(\s{{0,3}}{r}\b", window):
                out.append((w.start(), w.end(), literal, name))
                break
    return out


class InstallPayloadScanner(Scanner):
    name = "install_payload"
    rules = [
        RuleSpec(
            id=R_MASKED_REGISTRY,
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Install script installs a package from a registry address decoded at run time",
            description=(
                "A file that a package.json install script runs decodes a value (base64 or a "
                "character-code table) and passes it to `npm install --registry`. The address of "
                "the registry the second package comes from is not written in the package, so "
                "neither a reviewer nor a text search sees where the code is fetched from."
            ),
            recommendation=(
                "Do not install this version. An honest install step names its registry in plain "
                "text, or uses the default one."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
        RuleSpec(
            id=R_DNS_BEACON,
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Install script resolves a DNS name built from the machine's host name",
            description=(
                "A package.json install script, or a file it runs, calls a DNS lookup whose name "
                "includes `os.hostname()`. The lookup reaches the name server of the domain at "
                "install time, so whoever runs that server learns which machine installed the "
                "package; no HTTP request is involved."
            ),
            recommendation=(
                "Do not install this version. An install step has no reason to resolve a name "
                "that carries the host name."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
        RuleSpec(
            id=R_SHELL_RUNS_JS,
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Install script runs a .js file with a shell interpreter",
            description=(
                "A package.json install script starts `sh`, `bash` or `zsh` on a file named like "
                "JavaScript. The file reads as JavaScript to a reviewer or a JavaScript linter, "
                "but the shell executes its command substitutions, including any that sit inside "
                "a JavaScript block comment."
            ),
            recommendation=(
                "Do not install this version. Run JavaScript with node and shell scripts with "
                "a .sh name."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
        RuleSpec(
            id=R_SERVICE_TOKEN_WATCH,
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Install script registers a user service next to a token-validity check",
            description=(
                "A file that a package.json install script runs writes a systemd user unit or a "
                "macOS launch agent, and the same file tests whether a token was revoked "
                "(a 401 response, `revoked`, `Bad credentials`). A service that lives on after "
                "install and acts on token state is a dead-man switch, not a helper."
            ),
            recommendation=(
                "Do not install this version. Inspect what the registered service runs when the "
                "token check fails."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
        RuleSpec(
            id=R_PY_DOWNLOAD_EXEC,
            category=CATEGORY,
            severity=Severity.HIGH,
            title="setup.py downloads a file and starts that same file",
            description=(
                "setup.py, or an in-tree PEP 517 build backend (`backend-path` in pyproject.toml), "
                "saves a remote file (with `urlretrieve`, or by writing a requests / urllib / "
                "httpx response to it) and then starts the file it saved (subprocess / os.system "
                "on the same path). What runs is whatever the host serves when the package is "
                "installed; it is not in the package for review."
            ),
            recommendation=(
                "Do not install this version. An honest build step ships the code it runs, or "
                "downloads a pinned artifact and verifies its checksum first."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        found: dict[str, list[Evidence]] = {r.id: [] for r in self.rules}
        _shell_run, node_run = install_run_interpreters(index)
        backend = build_backend_files(index)
        for f in index.files:
            if f.name == "package.json":
                for _name, command, start, end in npm_install_commands(f, _LIFECYCLE):
                    if _DNS_WITH_HOSTNAME.search(command):
                        found[R_DNS_BEACON].append(f.evidence_for_span(start, end))
                    if _SHELL_ON_JS.search(command):
                        found[R_SHELL_RUNS_JS].append(f.evidence_for_span(start, end))
            elif f.relpath in index.install_scripts and (
                f.suffix in (".js", ".cjs", ".mjs") or f.relpath in node_run
            ):
                self._install_run_js(f, found)
            elif f.name == "setup.py" or f.relpath in backend:
                self._setup_py(f, found[R_PY_DOWNLOAD_EXEC])
        findings = [
            _finding_from_rule(rule, found[rule.id]) for rule in self.rules if found[rule.id]
        ]
        return ScanResult(findings=findings, needs_review=[])

    @staticmethod
    def _install_run_js(f: IndexedFile, found: dict[str, list[Evidence]]) -> None:
        text = f.text
        m = _REGISTRY_FROM_VALUE.search(text)
        if m and _DECODES_ADDRESS.search(text):
            found[R_MASKED_REGISTRY].append(f.evidence_for_span(m.start(), m.end()))
        m = _DNS_WITH_HOSTNAME.search(text)
        if m and not f.in_c_comment(m.start()):
            found[R_DNS_BEACON].append(f.evidence_for_span(m.start(), m.end()))
        m = _USER_SERVICE.search(text)
        if m and _TOKEN_REVOKED.search(text) and _TOKEN_WORD.search(text):
            found[R_SERVICE_TOKEN_WATCH].append(f.evidence_for_span(m.start(), m.end()))

    @staticmethod
    def _setup_py(f: IndexedFile, out: list[Evidence]) -> None:
        for start, end, literal, name in _py_downloads(f):
            if f.in_comment(start) or not (literal or name):
                continue
            target = re.escape(literal) if literal else rf"\b{re.escape(name)}\b"
            call = re.compile(
                rf"\b{_PY_EXEC_CALL}\(\s{{0,3}}(?:\[\s{{0,3}})?{_INTERPRETER_ARG}[\"']?{target}"
            )
            run = call.search(f.text, end)
            if run and not f.in_comment(run.start()):
                out.append(f.evidence_for_span(start, end))
                out.append(f.evidence_for_span(run.start(), run.end()))
                return


# `[build-system]` of a pyproject.toml: the backend pip imports to build the package, and the
# folders of the source tree it is imported from (`backend-path`, PEP 517's in-tree backend).
_BUILD_SYSTEM = re.compile(r"(?ms)^\[build-system\][ \t]*$(.{0,4000}?)(?=^\[|\Z)")
_BUILD_BACKEND = re.compile(
    r"""(?m)^build-backend\s*=\s*["']([A-Za-z_][\w.]{0,200})(?::[\w.]*)?["']"""
)
_BACKEND_PATH = re.compile(r"(?m)^backend-path\s*=\s*\[([^\]]{0,1000})\]")
_MAX_BACKEND_FILES = 20


def build_backend_files(index: FileIndex) -> set[str]:
    """Relative paths of the modules of an in-tree PEP 517 build backend: the module named by
    ``build-backend`` under a ``backend-path`` folder, and the modules it imports from those
    folders, transitively. pip imports them and calls ``build_wheel`` on install, before the
    package exists, exactly as it runs a ``setup.py``. A backend without ``backend-path`` is an
    installed tool (setuptools, hatchling), not code of this component."""
    known = {f.relpath: f for f in index.files}
    found: set[str] = set()
    for project in index.select(names=("pyproject.toml",)):
        section = _BUILD_SYSTEM.search(project.text)
        backend = _BUILD_BACKEND.search(section.group(1)) if section else None
        paths = _BACKEND_PATH.search(section.group(1)) if section else None
        if backend is None or paths is None:
            continue
        folder = posixpath.dirname(project.relpath)
        roots = [
            "" if root == "." else root
            for p in re.findall(r"""["']([^"'\n]{0,200})["']""", paths.group(1))
            for root in [posixpath.normpath(posixpath.join(folder, p))]
            if not root.startswith("..")
        ]
        parts = backend.group(1).split(".")
        queue = [
            rel for root in roots for k in range(1, len(parts) + 1)
            for rel in _module_paths(root, parts[:k]) if rel in known
        ]
        while queue and len(found) < _MAX_BACKEND_FILES:
            rel = queue.pop(0)
            if rel in found:
                continue
            found.add(rel)
            queue += [t for t in _python_targets(known[rel], roots) if t in known]
    return found
