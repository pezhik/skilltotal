"""Shell-script detection (.sh / .bash / .zsh and shebang scripts).

Shell install/bootstrap scripts are a common dropper surface that the language scanners
(Python AST, Node regex) miss: a decode-and-execute idiom (``… base64 -d | bash``) or a
remote pipe-to-shell (``curl … | sh``). Detection is regex over shell files, selected by
suffix or by a shell shebang on the first line.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
    alternation,
)

SHELL_SUFFIXES = (".sh", ".bash", ".zsh")
_SHEBANG_RE = re.compile(r"^#!.*\b(?:bash|zsh|sh|dash|ksh)\b")
# A shell that the decoded/fetched payload is piped or fed into.
_TO_SHELL = r"\|\s*(?:sudo\s+)?\b(?:bash|zsh|sh)\b"

R_DECODE_EXEC_SH = "ST-OBF-DECODE-EXEC-SH"
R_PIPE_EXEC = "ST-SHELL-PIPE-EXEC"
R_PASSWORD_ARCHIVE = "ST-ARCHIVE-PASSWORD-EXTRACT"  # nosec B105 - a rule id, not a password
# Markdown whose fenced shell blocks are commands for a person or an agent to run. The ClawHavoc
# skills (ClawHub, early 2026) put `echo '<base64>' | base64 -D | bash` under "Prerequisites".
_MARKDOWN = (".md", ".mdx")
# Fence info strings that mean "run this in a shell". A ```typescript block showing
# `sandbox.exec('curl ... | sh')` is a code sample, not a command (FP: a Cloudflare skill's
# reference file raised a registry MCP server from medium to high).
_SHELL_FENCES = frozenset(
    {"", "bash", "sh", "shell", "zsh", "console", "terminal", "shell-session"}
)
_FENCE_INFO = re.compile(r" {0,3}(?:`{3,}|~{3,})\s*([\w+-]*)")
# Rules that apply inside markdown. A pipe-to-shell there is an install instruction in prose docs
# far more often than anything else, so it stays a script-only signal; decoding-then-executing
# and extracting a downloaded archive with a password have no honest documentation reading.
_MARKDOWN_RULES = frozenset({R_DECODE_EXEC_SH, R_PASSWORD_ARCHIVE})
_DOWNLOAD = re.compile(r"\b(?:curl|wget|Invoke-WebRequest|iwr)\b", re.IGNORECASE)


class ShellScriptScanner(Scanner):
    """Custom scanner: regex rules over shell files (suffix or shebang)."""

    name = "shell_script"
    rules = [
        RuleSpec(
            id=R_DECODE_EXEC_SH,
            category="obfuscation",
            severity=Severity.HIGH,
            title="Shell decode-and-execute (obfuscated execution)",
            description=(
                "A shell command decodes data and immediately executes it "
                "(e.g. `… base64 -d | bash` or `eval \"$(… base64 -d)\"`). Decoding then "
                "executing hides behaviour from review and is a common dropper idiom."
            ),
            recommendation=(
                "Decode the payload manually and inspect what it runs before trusting this "
                "component. Never pipe decoded data into a shell."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            suffixes=SHELL_SUFFIXES,
            pattern=alternation(
                rf"base64\s+(?:-d|-D|--decode)\b[^\n]*{_TO_SHELL}",
                r"\beval\b[^\n]*\bbase64\s+(?:-d|-D|--decode)\b",
            ),
        ),
        RuleSpec(
            id=R_PIPE_EXEC,
            category="shell_execution",
            severity=Severity.HIGH,
            title="Remote pipe-to-shell execution",
            description=(
                "A remotely fetched payload is piped straight into a shell "
                "(e.g. `curl … | bash`). The component runs code downloaded at runtime, which "
                "is unreviewable and a common second-stage delivery vector."
            ),
            recommendation=(
                "Download to a file, inspect it, and run a pinned/verified copy instead of "
                "piping a network response directly into a shell."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.RISKY_CONSTRUCT,
            suffixes=SHELL_SUFFIXES,
            # A `# Usage: curl … | bash` line documents the install command; it is a comment, not
            # a runnable pipe-to-shell. Demote matches inside shell comments (engine code-context).
            code_context="comments",
            pattern=alternation(
                rf"(?:curl|wget)\b[^\n]*{_TO_SHELL}",
            ),
        ),
        RuleSpec(
            id=R_PASSWORD_ARCHIVE,
            category="obfuscation",
            severity=Severity.HIGH,
            title="Downloaded archive extracted with a password",
            description=(
                "A script or setup instruction downloads an archive and extracts it with a "
                "password (`unzip -P …`, `7z x -p…`). The password exists to keep the contents "
                "away from scanners on the way in; malicious agent skills (ToxicSkills, 2026) "
                "delivered their binaries this way."
            ),
            recommendation=(
                "Do not run it. Download the archive in isolation and inspect what it contains."
            ),
            capability=Capability.SHELL_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            suffixes=SHELL_SUFFIXES,
            code_context="comments",
            pattern=alternation(
                r"\bunzip\b[^\n]*\s-P\s*\S+",
                r"\b7za?\s+[xe]\b[^\n]*\s-p\S+",
                r"\bunrar\s+[xe]\b[^\n]*\s-p\S+",
            ),
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        files = [f for f in index.files if self._is_shell(f) or f.suffix in _MARKDOWN]
        findings = []
        for rule in self.rules:
            if rule.pattern is None:
                continue
            seen: set[tuple[str, int, int]] = set()
            evidence = []
            for f in files:
                if f.suffix in _MARKDOWN and rule.id not in _MARKDOWN_RULES:
                    continue
                regions = self._regions(f)
                for m, ev in f.finditer(rule.pattern):
                    region = next((r for r in regions if r[0] <= m.start() < r[1]), None)
                    if region is None:
                        continue
                    if rule.id == R_PASSWORD_ARCHIVE and not _DOWNLOAD.search(
                        f.text, region[0], region[1]
                    ):
                        continue
                    key = (ev.file, ev.line_start, ev.line_end)
                    if key in seen:
                        continue
                    seen.add(key)
                    evidence.append(ev)
                    if len(evidence) >= MAX_EVIDENCE_SCANNED:
                        break
            if evidence:
                findings.append(_finding_from_rule(rule, evidence))
        return ScanResult(findings=findings)

    @staticmethod
    def _regions(f) -> list[tuple[int, int]]:
        """Where shell commands live: the whole script, or each fenced block of a markdown file."""
        if f.suffix in _MARKDOWN:
            spans = []
            for start, end in f.markdown_code_spans():
                info = _FENCE_INFO.match(f.text, start)
                if info is not None and info.group(1).lower() in _SHELL_FENCES:
                    spans.append((start, end))
            return spans
        return [(0, len(f.text))]

    @staticmethod
    def _is_shell(f) -> bool:
        if f.suffix in SHELL_SUFFIXES:
            return True
        first = f.text[:200].splitlines()[0] if f.text else ""
        return bool(_SHEBANG_RE.match(first))
