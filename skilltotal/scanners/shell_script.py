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
    MAX_EVIDENCE_PER_FINDING,
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
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        files = [f for f in index.files if self._is_shell(f)]
        findings = []
        for rule in self.rules:
            if rule.pattern is None:
                continue
            seen: set[tuple[str, int, int]] = set()
            evidence = []
            for f in files:
                for _m, ev in f.finditer(rule.pattern):
                    key = (ev.file, ev.line_start, ev.line_end)
                    if key in seen:
                        continue
                    seen.add(key)
                    evidence.append(ev)
                    if len(evidence) >= MAX_EVIDENCE_PER_FINDING:
                        break
            if evidence:
                findings.append(_finding_from_rule(rule, evidence))
        return ScanResult(findings=findings)

    @staticmethod
    def _is_shell(f) -> bool:
        if f.suffix in SHELL_SUFFIXES:
            return True
        first = f.text[:200].splitlines()[0] if f.text else ""
        return bool(_SHEBANG_RE.match(first))
