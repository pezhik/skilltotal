"""Install-time payload shapes that the generic install-hook checks do not name.

Each rule here needs the install context (a lifecycle script of ``package.json``, a file one of
them runs, or ``setup.py``) AND a second tell that an honest install step does not have:

* a registry address decoded at run time and handed to a second ``npm install``;
* a DNS lookup whose name carries the machine's host name;
* a shell interpreter started on a ``.js`` file (JavaScript syntax hides shell substitutions);
* a user-level service or launch agent written next to a token-validity check;
* a build script that downloads a file and then starts that same file.

Detection patterns below are string literals; nothing here runs a command.
"""

from __future__ import annotations

import re

from skilltotal import bounded_json
from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import RuleSpec, Scanner, ScanResult, _finding_from_rule

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


def _lifecycle_commands(f: IndexedFile) -> list[tuple[str, int, int]]:
    """``(command, start, end)`` of each install-time script of a package.json (span = its key)."""
    try:
        data = bounded_json.loads(f.text)
    except ValueError:
        return []
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return []
    block = re.search(r'"scripts"\s*:', f.text)
    out: list[tuple[str, int, int]] = []
    for name in _LIFECYCLE:
        command = scripts.get(name)
        if not isinstance(command, str):
            continue
        key = re.compile(rf'"{name}"\s*:').search(f.text, block.end() if block else 0) or block
        out.append((command, key.start(), key.end()) if key else (command, 0, 1))
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
                "setup.py saves a remote file with `urlretrieve` and then starts the file it "
                "saved (subprocess / os.system on the same path). What runs is whatever the "
                "host serves when the package is installed; it is not in the package for review."
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
        for f in index.files:
            if f.name == "package.json":
                for command, start, end in _lifecycle_commands(f):
                    if _DNS_WITH_HOSTNAME.search(command):
                        found[R_DNS_BEACON].append(f.evidence_for_span(start, end))
                    if _SHELL_ON_JS.search(command):
                        found[R_SHELL_RUNS_JS].append(f.evidence_for_span(start, end))
            elif f.relpath in index.install_scripts and f.suffix in (".js", ".cjs", ".mjs"):
                self._install_run_js(f, found)
            elif f.name == "setup.py":
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
        for dl in _PY_DOWNLOAD.finditer(f.text):
            if f.in_comment(dl.start()):
                continue
            literal, name = dl.group(2), dl.group(3)
            target = re.escape(literal) if literal else rf"\b{re.escape(name)}\b"
            call = re.compile(
                rf"\b{_PY_EXEC_CALL}\(\s{{0,3}}(?:\[\s{{0,3}})?{_INTERPRETER_ARG}[\"']?{target}"
            )
            run = call.search(f.text, dl.end())
            if run and not f.in_comment(run.start()):
                out.append(f.evidence_for_span(dl.start(), dl.end()))
                out.append(f.evidence_for_span(run.start(), run.end()))
                return
