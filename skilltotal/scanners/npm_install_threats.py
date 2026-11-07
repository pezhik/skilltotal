"""Install-time shapes of malicious npm packages that no generic install-hook check names.

Every rule reads only the files npm runs at install (``FileIndex.install_scripts``: the file a
``preinstall`` / ``install`` / ``postinstall`` command starts and the modules it loads), so a
library that merely mentions one of these strings in its sources does not match. Each rule needs
two tells that an honest install step does not combine:

* ``ST-NPM-DEPCONF-BEACON`` - a dependency-confusion stub: the install code reads the machine's
  host name and sends it, with the working directory, to a bare public IP address.
* ``ST-NPM-SANDBOX-GATED-LOADER`` - install code that probes for an analysis environment
  (a tracer attached, a container cgroup, a CI runner) and, only past those checks, loads a
  native ``.node`` addon or starts a detached child.
* ``ST-INSTALL-MINER`` - an install script that carries a cryptocurrency miner's command line
  (donation level, a stratum pool URL, a mining algorithm flag).

Detection is regex over file text; nothing is executed.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import RuleSpec, Scanner, ScanResult, _finding_from_rule

CATEGORY = "install_time_execution"
R_DEPCONF_BEACON = "ST-NPM-DEPCONF-BEACON"
R_SANDBOX_GATED_LOADER = "ST-NPM-SANDBOX-GATED-LOADER"
R_INSTALL_MINER = "ST-INSTALL-MINER"

_JS_SUFFIXES = (".js", ".cjs", ".mjs", ".ts")

_HOSTNAME = re.compile(r"\bhostname\s{0,3}\(\s{0,3}\)")
_WORKDIR = re.compile(r"\bprocess\s{0,3}\.\s{0,3}cwd\s{0,3}\(|\b__dirname\b")
_NET_CLIENT = re.compile(
    r"\b(?:https?|net|tls|dgram)\s{0,3}\.\s{0,3}(?:request|get|connect|createSocket)\s{0,3}\("
    r"|\bfetch\s{0,3}\(|\baxios\b|\bXMLHttpRequest\b|\bsendBeacon\b"
)
_IPV4 = re.compile(
    r"""["'`](?:https?://)?(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?::\d{1,5})?"""
    r"""(?:/[^"'`\s]{0,100})?["'`]"""
)

_CI_ENV = re.compile(r"\b(?:GITHUB_ACTIONS|GITLAB_CI|JENKINS_URL|TRAVIS|CIRCLECI|BUILDKITE)\b")
_TRACER = re.compile(r"\bTracerPid\b")
_CGROUP = re.compile(r"/proc/(?:1|self)/cgroup\b")
_NODE_ADDON = re.compile(
    r"""\brequire\s{0,3}\(\s{0,3}["']\.{1,2}/[^"'\n]{0,100}\.node["']\s{0,3}\)"""
)
_DETACHED = re.compile(r"\bdetached\s{0,3}:\s{0,3}true\b|\bsetsid\b")

_MINER = re.compile(
    r"--donate-level\b"
    r"|\bstratum\+(?:tcp|ssl)://"
    r"|--algo[= ]\s{0,3}(?:rx/0|randomx|cryptonight)"
    r"|(?:^|[\s/;&|])xmrig\w{0,12}(?=[\s\"';&|]|$)",
    re.IGNORECASE | re.MULTILINE,
)


def _public_ipv4(octets: tuple[str, ...]) -> bool:
    a, b, c, d = (int(o) for o in octets)
    if max(a, b, c, d) > 255 or a in (0, 10, 127) or a >= 224:
        return False
    if (a, b) in ((169, 254), (192, 168)) or (a == 172 and 16 <= b <= 31):
        return False
    return True


def _install_files(index: FileIndex) -> list[IndexedFile]:
    return [f for f in index.files if f.relpath in index.install_scripts]


class NpmInstallThreatsScanner(Scanner):
    name = "npm_install_threats"
    rules = [
        RuleSpec(
            id=R_DEPCONF_BEACON,
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Install script sends the host name to a bare IP address",
            description=(
                "Code that npm runs when this package is installed reads the machine's host name "
                "and working directory and sends them through a network client to a literal "
                "public IP address. Installing a package has no reason to report the machine to "
                "an address with no name; this is the callback of a dependency-confusion stub "
                "that has been published to see which internal builds install it."
            ),
            recommendation=(
                "Do not install this package. If it was installed, check which internal name "
                "it shadows, pin that name to your own registry scope, and rotate secrets "
                "reachable from the build machine."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            code_context="comments",
        ),
        RuleSpec(
            id=R_SANDBOX_GATED_LOADER,
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Install script checks for an analysis environment before loading a payload",
            description=(
                "Code that npm runs when this package is installed reads a debugger marker "
                "(TracerPid) or a container cgroup, checks for a CI runner, and loads a native "
                ".node addon or starts a detached child. An install step has no reason to find "
                "out whether it is being analyzed; the gate keeps the payload from running in "
                "sandboxes and CI."
            ),
            recommendation=(
                "Do not install this package. Open the native addon in a disassembler or a "
                "sandbox before trusting it."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            code_context="comments",
        ),
        RuleSpec(
            id=R_INSTALL_MINER,
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Install script carries a cryptocurrency miner command line",
            description=(
                "A file npm runs when this package is installed contains a miner's command line: "
                "a donation-level flag, a stratum pool URL, a mining-algorithm flag or the "
                "xmrig program. Installing a package has no reason to start a miner on the "
                "machine."
            ),
            recommendation=(
                "Do not install this package. If it was installed, kill the miner process and "
                "remove its persistence (cron entries, systemd units)."
            ),
            capability=Capability.INSTALL_TIME_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            code_context="comments",
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        beacon: list[Evidence] = []
        gated: list[Evidence] = []
        miner: list[Evidence] = []
        for f in _install_files(index):
            if f.suffix in _JS_SUFFIXES:
                beacon.extend(_beacon(f))
                gated.extend(_gated(f))
            m = _MINER.search(f.text)
            if m is not None:
                miner.append(f.evidence_for_span(m.start(), m.end()))
        findings = [
            _finding_from_rule(rule, evidence)
            for rule, evidence in zip(self.rules, (beacon, gated, miner), strict=True)
            if evidence
        ]
        return ScanResult(findings=findings)


def _beacon(f: IndexedFile) -> list[Evidence]:
    text = f.text
    host = _HOSTNAME.search(text)
    if host is None or _WORKDIR.search(text) is None or _NET_CLIENT.search(text) is None:
        return []
    for m in _IPV4.finditer(text):
        if _public_ipv4(m.groups()):
            return [f.evidence_for_span(host.start(), host.end()),
                    f.evidence_for_span(m.start(), m.end())]
    return []


def _gated(f: IndexedFile) -> list[Evidence]:
    text = f.text
    probe = _TRACER.search(text) or _CGROUP.search(text)
    if probe is None:
        return []
    markers = sum(1 for p in (_CI_ENV, _TRACER, _CGROUP) if p.search(text))
    if markers < 2:
        return []
    action = _NODE_ADDON.search(text) or _DETACHED.search(text)
    if action is None:
        return []
    return [f.evidence_for_span(probe.start(), probe.end()),
            f.evidence_for_span(action.start(), action.end())]
