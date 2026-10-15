"""Install-time execution detection (npm lifecycle hooks, Python build hooks).

Install-time hooks run automatically when a user installs a package — a classic supply
chain execution vector. npm hooks are matched directly on ``package.json``; Python's
``setup.py`` is only flagged when it contains execution-y constructs (a bare ``setup()``
call is not, by itself, suspicious).
"""

from __future__ import annotations

import re

from skilltotal import bounded_json
from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import (
    PatternScanner,
    RuleSpec,
    ScanResult,
    _finding_from_rule,
    alternation,
)
from skilltotal.scanners.obfuscation import _DECODE_EXEC
from skilltotal.scanners.shell_script import DECODE_EXEC_SH, REMOTE_EXEC

CATEGORY = "install_time_execution"
R_NPM_REMOTE_EXEC = "ST-INSTALL-NPM-REMOTE-EXEC"
# The scripts npm runs on its own: on every install of the package (preinstall / install /
# postinstall), and on a git or local install (prepare).
_NPM_LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")


def runs_fetched_or_decoded_code(command: str) -> bool:
    """True if a command downloads code and runs it, or decodes data and runs it: the shell forms
    (`curl … | sh`, `sh -c "$(curl …)"`, `… base64 -d | sh`) and inline JavaScript or Python
    (`node -e "eval(Buffer.from(…, 'base64').toString())"`)."""
    return bool(
        REMOTE_EXEC.search(command) or DECODE_EXEC_SH.search(command)
        or _DECODE_EXEC.search(command)
    )


class InstallScriptsScanner(PatternScanner):
    name = "install_scripts"
    rules = [
        RuleSpec(
            id="ST-INSTALL-NPM",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="npm install-time lifecycle hook",
            description=(
                "package.json declares install-time lifecycle scripts "
                "(preinstall / install / postinstall) that run automatically when the "
                "package is installed by a consumer."
            ),
            recommendation=(
                "Inspect the hook command. Install-time scripts are a common supply chain "
                "execution vector; ensure they do nothing beyond a documented build step."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            names=("package.json",),
            pattern=re.compile(r'"(?:preinstall|install|postinstall)"\s*:'),
        ),
        RuleSpec(
            id="ST-INSTALL-NPM-PREPARE",
            category=CATEGORY,
            severity=Severity.MEDIUM,
            title="npm prepare hook",
            description=(
                "package.json declares a 'prepare' script. It runs on local/git installs "
                "and before publish (typically a build step), but not for consumers "
                "installing the published package from the registry."
            ),
            recommendation=(
                "Usually a legitimate build step; confirm it only builds and does not fetch "
                "or execute remote code."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            names=("package.json",),
            pattern=re.compile(r'"prepare"\s*:'),
        ),
        RuleSpec(
            id=R_NPM_REMOTE_EXEC,
            category=CATEGORY,
            severity=Severity.HIGH,
            title="npm install script downloads or decodes code and runs it",
            description=(
                "A package.json lifecycle script that npm runs on its own (preinstall / install / "
                "postinstall, or prepare on a git or local install) downloads code and pipes it "
                "into a shell, or decodes data and executes it, for example "
                "`curl -fsSL https://… | bash` or `node -e \"eval(Buffer.from(…, 'base64')…)\"`. "
                "What runs is whatever the host serves, or the decoded text, on every install; "
                "neither is in the package for review."
            ),
            recommendation=(
                "Do not install this version. An honest package ships the code its install step "
                "runs, or downloads a pinned artifact and verifies its checksum before using it."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            # Custom matching (InstallScriptsScanner.scan): the parsed script values of each
            # package.json, so a JSON escape (`|` for `|`) is read as npm reads it.
            names=("package.json",),
        ),
        RuleSpec(
            id="ST-INSTALL-GYP",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="binding.gyp runs a hidden command at install time",
            description=(
                "binding.gyp uses node-gyp command substitution (`<!(…)`) to run a script with "
                "its output discarded, fetch from the network, pipe into a shell, or decode "
                "data. node-gyp evaluates it during `npm install` even when package.json "
                "declares no install script, so install-script checks never see it, for example "
                "`<!(node index.js > /dev/null 2>&1 && echo stub.c)`."
            ),
            recommendation=(
                "Do not install this version. Honest bindings use substitution only to print "
                "include paths (`node -p \"require('node-addon-api').include\"`)."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            names=("binding.gyp",),
            pattern=re.compile(
                r"<!@?\(\s*(?:"
                r"[^)\"']*?\b(?:curl|wget)\b"
                r"|[^)\"']*?https?://"
                r"|[^)\"']*?\|\s*(?:ba|z)?sh\b"
                r"|[^)\"']*?\bbase64\b"
                r"|node\s+(?!-[pe]\b)[^\s)\"']+\.[cm]?js\b[^)\"']*?(?:>\s*/dev/null|2>&1|>\s*nul\b)"
                r")",
                re.IGNORECASE,
            ),
        ),
        RuleSpec(
            id="ST-INSTALL-PY",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Python install/build-time execution hook",
            description=(
                "setup.py / pyproject build configuration contains execution constructs "
                "(custom cmdclass, command-class override, subprocess/os.system, eval/exec, "
                "or network access) that run at build/install time."
            ),
            recommendation=(
                "Verify the build hook performs only a legitimate build step and does not "
                "execute commands or reach the network during installation."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            names=("setup.py", "pyproject.toml"),
            pattern=alternation(
                r"\bcmdclass\b",
                r"class\s+\w*(?:Install|Develop|EggInfo|BuildPy|Build)\b",
                r"\bos\.system\s*\(",
                r"\bsubprocess\.",
                r"\beval\s*\(",
                r"\bexec\s*\(",
                r"\bimport\s+(?:urllib|requests|socket|http)\b",
                flags=re.MULTILINE,
            ),
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        result = super().scan(index)
        evidence = [
            ev for f in index.select(names=("package.json",)) for ev in _remote_exec_scripts(f)
        ]
        if evidence:
            rule = next(r for r in self.rules if r.id == R_NPM_REMOTE_EXEC)
            result.findings.append(_finding_from_rule(rule, evidence))
        return result


def _remote_exec_scripts(f: IndexedFile) -> list[Evidence]:
    """Evidence for each lifecycle script of ``f`` (a package.json) that runs fetched or decoded
    code. The values are read as npm reads them (JSON-decoded); each evidence points at the line of
    the script's key, or at the ``scripts`` key when the key itself is written with escapes."""
    try:
        data = bounded_json.loads(f.text)
    except ValueError:
        return []
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return []
    found: list[Evidence] = []
    block = re.search(r'"scripts"\s*:', f.text)
    for name in _NPM_LIFECYCLE_SCRIPTS:
        command = scripts.get(name)
        if not isinstance(command, str) or not runs_fetched_or_decoded_code(command):
            continue
        key = re.compile(rf'"{name}"\s*:').search(f.text, block.end() if block else 0) or block
        start, end = (key.start(), key.end()) if key else (0, 1)
        found.append(f.evidence_for_span(start, end))
    return found
