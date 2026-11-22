"""Package install and start-up shapes that report or run something an honest package does not.

Four shapes seen in recent PyPI and npm malware write-ups. Each needs two tells together:

* ``ST-NPM-INSTALL-RECON-BEACON`` - an install-time command that runs a machine query (``id``,
  ``whoami``, ``hostname``, ``uname``), base64-encodes the output and sends it with ``curl`` or
  ``wget`` to a URL (a dependency-confusion probe).
* ``ST-PY-SETUP-EXE-LAUNCH`` - a ``setup.py`` that overrides an install-time command class and
  starts a Windows ``.exe`` file.
* ``ST-PY-MAIN-BUNDLED-EXE-HIDDEN`` - a module entry point (``__main__.py``) that starts an
  ``.exe`` file found next to the module, hidden or detached from the console.
* ``ST-PY-DEP-PLAIN-HTTP-URL`` - a package declaration whose dependency is a direct reference to
  a plain ``http://`` address (``name @ http://host/file``) instead of a registry name.

Detection is regex over file text; nothing is executed.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.loaded_code import NPM_LIFECYCLE_SCRIPTS
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    TACTIC_COMMAND_AND_CONTROL,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
)
from skilltotal.scanners.install_scripts import npm_install_commands

CATEGORY = "install_time_execution"
R_NPM_RECON_BEACON = "ST-NPM-INSTALL-RECON-BEACON"  # nosec B105 - rule id, not a credential
R_SETUP_EXE = "ST-PY-SETUP-EXE-LAUNCH"  # nosec B105 - rule id, not a credential
R_MAIN_EXE = "ST-PY-MAIN-BUNDLED-EXE-HIDDEN"  # nosec B105 - rule id, not a credential
R_DEP_HTTP = "ST-PY-DEP-PLAIN-HTTP-URL"  # nosec B105 - rule id, not a credential

# A machine query at the start of a command, or right after a separator or `$(` / backtick.
_RECON = r"(?:id|whoami|hostname|uname|pwd)"
_RECON_AT = rf"(?:^|[;&|(`]|\$\()\s{{0,3}}{_RECON}\b"
_RECON_BEACON = re.compile(
    rf"{_RECON_AT}[^\n]{{0,100}}?\bbase64\b[^\n]{{0,150}}?\b(?:curl|wget)\b[^\n]{{0,250}}?https?://"
    rf"|\b(?:curl|wget)\b[^\n]{{0,250}}?(?:\$\(|`)\s{{0,3}}{_RECON}\b[^\n]{{0,100}}?\bbase64\b"
)

_CMDCLASS = re.compile(r"\bcmdclass\b")
_CMD_BASE = re.compile(
    r"\bclass\s+\w+\s*\([^)\n]{0,80}\b(?:install|develop|egg_info|build_py|build_ext|bdist_wheel)\b"
)
_EXE_LITERAL = re.compile(r"[\"'][^\"'\n]{0,150}\.exe[\"']", re.IGNORECASE)
_LAUNCH = re.compile(
    r"\bsubprocess\.(?:Popen|run|call|check_call|check_output)\s*\("
    r"|\bos\.(?:startfile|system|popen|spawn[lv]p?e?)\s*\("
)
_HIDDEN = re.compile(
    r"\bCREATE_NO_WINDOW\b|\bDETACHED_PROCESS\b|\bSW_HIDE\b|\bSTARTF_USESHOWWINDOW\b"
    r"|\bstart_new_session\s*=\s*True\b|\bcreationflags\s*=|\bstartupinfo\s*="
)
_FILE_ANCHOR = re.compile(r"\b__file__\b|\bimportlib\.resources\b|\bfiles\s*\(\s*__package__")

# `name @ http://host/path` (PEP 508 direct reference) in a quoted or listed dependency.
_HTTP_DIRECT_REF = re.compile(
    r"(?:^|[\s\"',\[])[A-Za-z0-9][A-Za-z0-9._-]{0,60}(?:\[[\w,\s-]{1,40}\])?[ \t]{0,3}@[ \t]{0,3}"
    r"http://(?P<host>[^\s\"',\]/:?#]{1,100})"
)
_LOOPBACK = re.compile(r"^(?:localhost|127\.\d+\.\d+\.\d+)$", re.IGNORECASE)
_DEP_FILES = ("setup.py", "setup.cfg", "pyproject.toml")


def _line_is_comment(f: IndexedFile, offset: int) -> bool:
    start = f.text.rfind("\n", 0, offset) + 1
    return f.text[start:offset].lstrip().startswith("#")


class InstallReconScanner(Scanner):
    name = "install_recon"
    rules = [
        RuleSpec(
            id=R_NPM_RECON_BEACON,
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Install command base64-encodes a machine query and sends it with curl or wget",
            description=(
                "A command that npm runs when this package is installed runs a machine query "
                "(id, whoami, hostname, uname), base64-encodes its output and sends it to a URL "
                "with curl or wget. Installing a package has no reason to report who and where "
                "the installer is; this is the callback of a dependency-confusion probe."
            ),
            recommendation=(
                "Do not install this package. If it was installed, find which internal name it "
                "shadows, pin that name to your own registry and treat the build machine as "
                "disclosed."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            tactic=TACTIC_COMMAND_AND_CONTROL,
        ),
        RuleSpec(
            id=R_SETUP_EXE,
            category=CATEGORY,
            severity=Severity.HIGH,
            title="setup.py install command starts an .exe file",
            description=(
                "setup.py overrides an install-time command class and, in the same file, starts "
                "a Windows executable (an .exe path passed to subprocess, os.startfile or "
                "os.system). Installing a Python package compiles or copies files; it does not "
                "run a program that ships inside it."
            ),
            recommendation=(
                "Do not install this package. Inspect the executable in a sandbox; a later "
                "release can swap it for something else."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            names=("setup.py",),
            tactic=TACTIC_COMMAND_AND_CONTROL,
        ),
        RuleSpec(
            id=R_MAIN_EXE,
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Module entry point starts a bundled .exe file hidden from the console",
            description=(
                "A __main__ module starts an .exe file found next to it (a path built from "
                "__file__ or package resources) with a hidden-window or detached process flag, "
                "so `python -m package` runs a bundled program the user does not see."
            ),
            recommendation=(
                "Do not run the module. Inspect the bundled executable in a sandbox before "
                "trusting the package."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            names=("__main__.py",),
            tactic=TACTIC_COMMAND_AND_CONTROL,
        ),
        RuleSpec(
            id=R_DEP_HTTP,
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Package declares a dependency as a direct reference to a plain http address",
            description=(
                "setup.py, setup.cfg or pyproject.toml lists a dependency as "
                "`name @ http://host/...` instead of a registry name. "
                "The package manager downloads the file from that host over an unencrypted "
                "connection when the package is installed, so the host sees every "
                "install and whoever is on the path can replace the file."
            ),
            recommendation=(
                "Do not install this package. A published package depends on registry names, "
                "not on a file at a plain http address."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            names=_DEP_FILES,
            tactic=TACTIC_COMMAND_AND_CONTROL,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        rules = {r.id: r for r in self.rules}
        found: dict[str, list[Evidence]] = {rid: [] for rid in rules}
        for f in index.files:
            name = f.name.lower()
            if name == "package.json":
                for _n, command, start, end in npm_install_commands(f, NPM_LIFECYCLE_SCRIPTS):
                    if _RECON_BEACON.search(command):
                        found[R_NPM_RECON_BEACON].append(f.evidence_for_span(start, end))
            elif f.relpath in index.install_scripts and f.suffix == ".sh":
                m = _RECON_BEACON.search(f.text)
                if m and not _line_is_comment(f, m.start()):
                    found[R_NPM_RECON_BEACON].append(f.evidence_for_span(m.start(), m.end()))
            if name == "setup.py":
                self._setup_exe(f, found[R_SETUP_EXE])
            elif name == "__main__.py":
                self._main_exe(f, found[R_MAIN_EXE])
            if name in _DEP_FILES:
                self._http_dep(f, found[R_DEP_HTTP])
        findings = [_finding_from_rule(rules[rid], ev) for rid, ev in found.items() if ev]
        return ScanResult(findings=findings)

    @staticmethod
    def _setup_exe(f: IndexedFile, out: list[Evidence]) -> None:
        text = f.text
        if ".exe" not in text.lower() or not _CMDCLASS.search(text) or not _CMD_BASE.search(text):
            return
        for exe in _EXE_LITERAL.finditer(text):
            if f.in_comment(exe.start()):
                continue
            launch = _LAUNCH.search(text)
            if launch and not f.in_comment(launch.start()):
                out.append(f.evidence_for_span(exe.start(), exe.end()))
                return

    @staticmethod
    def _main_exe(f: IndexedFile, out: list[Evidence]) -> None:
        text = f.text
        if ".exe" not in text.lower() or not _FILE_ANCHOR.search(text):
            return
        exe = _EXE_LITERAL.search(text)
        launch = _LAUNCH.search(text)
        hidden = _HIDDEN.search(text)
        if exe and launch and hidden and not f.in_comment(launch.start()):
            out.append(f.evidence_for_span(exe.start(), exe.end()))

    @staticmethod
    def _http_dep(f: IndexedFile, out: list[Evidence]) -> None:
        if "http://" not in f.text:
            return
        for m in _HTTP_DIRECT_REF.finditer(f.text):
            if len(out) >= MAX_EVIDENCE_SCANNED:
                break
            if _LOOPBACK.match(m.group("host")) or _line_is_comment(f, m.start()):
                continue
            out.append(f.evidence_for_span(m.start(), m.end()))
