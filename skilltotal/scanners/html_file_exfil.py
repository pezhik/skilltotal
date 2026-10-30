"""An HTML page that reads local files through ``file://`` and sends them out.

A preview pane that renders an HTML file from the project runs its script with the page's own
privileges. A page that fetches a ``file:///`` URL (``fetch`` or ``XMLHttpRequest``) and, in the
same page, sends data out through ``navigator.sendBeacon``, a ``fetch``/``XMLHttpRequest`` to an
``http(s)`` URL, or a ``WebSocket`` is built to read a local file and ship it. An honest page
links to ``file://`` documents or fetches its own assets and a web API; reading a local file and
sending data off the machine in one page has no such use. Both halves must be present.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import RuleSpec, Scanner, ScanResult, _finding_from_rule

R_HTML_FILE_URL_EXFIL = "ST-HTML-FILE-URL-EXFIL"

_HTML = re.compile(r"\.html?$", re.IGNORECASE)
# A script call that reads a local file: fetch("file:///..."), xhr.open("GET", "file:///...").
_FILE_READ = re.compile(
    r"\b(?:fetch|open)\s*\(\s*(?:[\"'`]?[A-Za-z]{3,8}[\"'`]\s*,\s*)?[\"'`]file:///",
    re.IGNORECASE,
)
# A script call that sends data off the page.
_SEND_OUT = re.compile(
    r"\bnavigator\s*\.\s*sendBeacon\s*\("
    r"|\bnew\s+WebSocket\s*\(\s*[\"'`]wss?://"
    r"|\bfetch\s*\(\s*[\"'`]https?://[^\"'`\n]{1,200}[\"'`]\s*,\s*\{[^}\n]{0,200}\bmethod\s*:\s*"
    r"[\"'`]POST"
    r"|\.open\s*\(\s*[\"'`]POST[\"'`]\s*,\s*[\"'`]https?://",
    re.IGNORECASE,
)


class HtmlFileExfilScanner(Scanner):
    name = "html_file_exfil"
    rules = [
        RuleSpec(
            id=R_HTML_FILE_URL_EXFIL,
            category="exfiltration_path",
            severity=Severity.HIGH,
            title="HTML page reads a local file through file:// and sends data out",
            description=(
                "An HTML page's script fetches a file:/// URL and, in the same page, sends data "
                "out with navigator.sendBeacon, a POST request to an http(s) URL or a WebSocket. "
                "Rendered in a preview pane or a browser, the page runs with access to local "
                "files and can ship what it reads to another host."
            ),
            recommendation=(
                "Do not open or preview this page. Remove the file:// read or the outbound call."
            ),
            capability=Capability.NETWORK_EGRESS,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        for f in index.files:
            if not _HTML.search(f.relpath):
                continue
            read = _FILE_READ.search(f.text)
            if read is None:
                continue
            send = _SEND_OUT.search(f.text)
            if send is None:
                continue
            evidence.append(f.evidence_for_span(read.start(), read.end()))
            evidence.append(f.evidence_for_span(send.start(), send.end()))
        if evidence:
            return ScanResult(findings=[_finding_from_rule(self.rules[0], evidence)])
        return ScanResult()
