"""Two runtime shapes of a trojaned package that the generic network and process rules do not join.

* ``ST-NODE-DOWNLOAD-RUN-SCRIPT``: a Node.js file downloads a Windows script (``.bat``, ``.cmd``,
  ``.ps1``, ``.vbs``, ``.hta``) into the temporary folder and starts that same file with a
  ``child_process`` call. The script is not in the package; the host that serves it decides what
  runs. Downloading a data file, or saving a script without starting it, is not this.
* ``ST-TELEGRAM-SESSION-EXFIL``: one file talks to the Telegram bot API, names where the Telegram
  desktop client keeps its login session (``tdata``) and uploads a file. A bot that only sends a
  message or a report names no session store.

Matching is by the same path literal or the same variable name inside one file; nothing is run.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Severity, ThreatClass
from skilltotal.scanners.base import RuleSpec, Scanner, ScanResult, _finding_from_rule

R_NODE_DOWNLOAD_RUN = "ST-NODE-DOWNLOAD-RUN-SCRIPT"
R_TELEGRAM_SESSION = "ST-TELEGRAM-SESSION-EXFIL"

_NODE_SUFFIXES = (".js", ".cjs", ".mjs", ".ts", ".mts", ".cts")
_CODE_SUFFIXES = (*_NODE_SUFFIXES, ".py", ".pyw")

# --- Node.js: a downloaded script in the temporary folder, then started ---------------------
_REQUEST = re.compile(
    r"(?<![\w$.])fetch\s*\(|\baxios\b|\bgot\s*\(|\bhttps?\s*\.\s*(?:get|request)\s*\("
    r"|\brequire\(\s*[\"'](?:node:)?https?[\"']\s*\)\s*\.\s*(?:get|request)\s*\("
)
_SCRIPT_LITERAL = re.compile(
    r"[\"'`](?P<path>[^\"'`\n]{0,80}?(?P<base>[\w.-]{1,60}\.(?:bat|cmd|ps1|vbs|hta)))[\"'`]",
    re.IGNORECASE,
)
_TEMP_FOLDER = re.compile(
    r"\btmpdir\s*\(|\bprocess\s*\.\s*env\s*\.\s*(?:TEMP|TMP|TMPDIR)\b|%TEMP%|%TMP%|[\"'`]/tmp\b",
    re.IGNORECASE,
)
_BINDING = re.compile(
    r"(?:\b(?:const|let|var)\s+)?(?<![\w$])([A-Za-z_$][\w$]{0,40})\s*=\s*[^;\n]{0,160}$"
)
_WRITE_CALL = re.compile(
    r"\b(?:createWriteStream|writeFile|writeFileSync|copyFile|copyFileSync|pipeline)\s*\("
    r"(?P<args>[^\n;]{0,200})"
)
_RUN_CALL = re.compile(
    r"(?<![\w$.])(?:(?:child_process|cp)\s*\.\s*)?"
    r"(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\((?P<args>[^\n;]{0,200})"
)


def _uses(args: str, names: set[str]) -> bool:
    return any(re.search(r"(?<![\w$.])" + re.escape(n) + r"(?![\w$])", args) for n in names)


def _download_run_evidence(f: IndexedFile) -> list[Evidence]:
    text = f.text
    if not _REQUEST.search(text) or not _TEMP_FOLDER.search(text):
        return []
    for lit in _SCRIPT_LITERAL.finditer(text):
        if f.in_c_comment(lit.start()):
            continue
        line_start = text.rfind("\n", 0, lit.start()) + 1
        bound = _BINDING.search(text[max(line_start, lit.start() - 200) : lit.start()])
        names = {lit.group("path"), lit.group("base")}
        if bound is not None:
            names.add(bound.group(1))
        write = next(
            (w for w in _WRITE_CALL.finditer(text) if _uses(w.group("args"), names)
             and not f.in_c_comment(w.start())),
            None,
        )
        run = next(
            (r for r in _RUN_CALL.finditer(text) if _uses(r.group("args"), names)
             and r.start() > lit.start() and not f.in_c_comment(r.start())),
            None,
        )
        if write is not None and run is not None:
            return [f.evidence_for_span(lit.start(), lit.end()),
                    f.evidence_for_span(write.start(), write.end()),
                    f.evidence_for_span(run.start(), run.end())]
    return []


# --- Telegram bot API plus the desktop client's session folder, and an upload ------------------
_TELEGRAM_API = re.compile(r"api\.telegram\.org", re.IGNORECASE)
_SESSION_STORE = re.compile(r"(?<![\w.-])tdata(?![\w-])|Telegram\s?Desktop", re.IGNORECASE)
_UPLOAD = re.compile(
    r"\bsend(?:Document|MediaGroup)\b|\bfiles\s*=|\bFormData\b|\bform-data\b|\bcreateReadStream\b"
)


def _telegram_evidence(f: IndexedFile) -> list[Evidence]:
    text = f.text
    api = _TELEGRAM_API.search(text)
    store = _SESSION_STORE.search(text)
    upload = _UPLOAD.search(text)
    if api is None or store is None or upload is None:
        return []
    return [f.evidence_for_span(m.start(), m.end()) for m in (api, store, upload)]


class TrojanRuntimeScanner(Scanner):
    name = "trojan_runtime"
    rules = [
        RuleSpec(
            id=R_NODE_DOWNLOAD_RUN,
            category="dynamic_code",
            severity=Severity.HIGH,
            title="Node.js downloads a script to the temp folder and runs it",
            description=(
                "A JavaScript file requests a URL, saves a Windows script (.bat, .cmd, .ps1, "
                ".vbs, .hta) under the temporary folder and starts that same path with a "
                "child_process call. What runs is whatever the remote host serves; it is not in "
                "the package for review."
            ),
            recommendation=(
                "Ship the script that runs, or download a pinned artifact and verify its "
                "checksum before starting it."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            suffixes=_NODE_SUFFIXES,
        ),
        RuleSpec(
            id=R_TELEGRAM_SESSION,
            category="exfiltration",
            severity=Severity.HIGH,
            title="Telegram bot upload next to the Telegram desktop session folder",
            description=(
                "One file uses the Telegram bot API, names the folder where the Telegram "
                "desktop client keeps its login session (tdata) and uploads a file. Together "
                "they move a logged-in Telegram session to a chat the author controls."
            ),
            recommendation=(
                "Do not run this component. A bot that reports status sends text or its own "
                "logs and has no reason to name another application's session store."
            ),
            capability=Capability.NETWORK_EGRESS,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            suffixes=_CODE_SUFFIXES,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        found: dict[str, list[Evidence]] = {r.id: [] for r in self.rules}
        for f in index.select(suffixes=_CODE_SUFFIXES):
            if f.suffix in _NODE_SUFFIXES:
                found[R_NODE_DOWNLOAD_RUN] += _download_run_evidence(f)
            found[R_TELEGRAM_SESSION] += _telegram_evidence(f)
        return ScanResult(
            findings=[_finding_from_rule(r, found[r.id][:6]) for r in self.rules if found[r.id]]
        )
