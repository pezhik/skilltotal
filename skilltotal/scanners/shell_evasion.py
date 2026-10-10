"""Defense-evasion OS-command idioms.

Beyond plain shell execution, real droppers use a small set of unmistakable evasion idioms:
PowerShell execution-policy bypass / encoded commands / hidden windows, macOS code-signing
bypass, and launching a payload detached from a world-writable temp dir. These are rarely benign;
flagged as a risky construct (not a malware verdict on their own — convergence elevates when they
co-occur with other malicious indicators).
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Evidence, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
    alternation,
)

# Where these idioms appear: shell, PowerShell, batch, and source that shells out.
_EVASION_SUFFIXES = (
    ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".pyw",
)
_JS_FAMILY = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})

R_SHELL_EVASION = "ST-SHELL-EVASION"

# -EncodedCommand hides the command it runs when the payload arrives as an opaque base64 blob.
# Node tools also use it to hand PowerShell a multi-line script without quoting problems, encoding
# a script they carry in clear text: `"-EncodedCommand", Buffer.from(SCRIPT, "utf16le")
# .toString("base64")` (gemini-cli's Windows ACL check, VS Code-style extensions). There nothing is
# hidden from a reader -- the script is in the same file and is scanned as text -- so that one shape
# is set aside for review. A literal blob, or a value encoded from anything else (a download, a file
# read, a parameter), stays a finding.
_ENCODED_FLAG = re.compile(r"(?i)-encodedcommand")
# The argv element after the flag: the encoding written inline, or the name holding it.
_NEXT_ARG = re.compile(
    r"""['"`]?\s*,\s*(?:(Buffer\.from\s*\()|([A-Za-z_$][\w$]*)\b(?![\w$]*\s*[(.\[]))"""
)
# What follows the script in `Buffer.from(<script>, "utf16le").toString("base64")`.
_UTF16_BASE64_TAIL = re.compile(
    r"""\s*,\s*['"](?:utf-?16le|ucs-?2)['"]\s*,?\s*\)\s*\.toString\(\s*['"]base64['"]\s*\)""",
    re.IGNORECASE,
)
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
_LOOKAHEAD_CHARS = 200
_BUILDER_BODY_CHARS = 6000
# A script builder that reaches outside the file (network, files, environment, input) is not a
# script the file spells out, whatever it returns.
_BUILDER_IO = re.compile(
    r"\b(?:fetch|axios|request|got|https?|net|readFile\w*|createReadStream|require|import|"
    r"XMLHttpRequest|WebSocket|stdin|argv|env|await)\b"
)
# The builder must carry the script itself, not only wrap its arguments (`` `${x}` ``).
_INTERPOLATION = re.compile(r"\$\{[^}]*\}")
_MIN_BUILDER_SCRIPT = 40
# Encoded-command exemption checks per file (each one may re-read the file).
_MAX_CHECKS = 8


def _bindings(f: IndexedFile, name: str) -> list[re.Match[str]]:
    """Every assignment of ``name`` in the file: `const|let|var <name> =` and `<name> =`."""
    return list(re.finditer(
        rf"(?<![\w$.])(?:(?:const|let|var)\s+)?{re.escape(name)}\s*(?::[^=\n]{{0,60}})?"
        rf"=(?![=>])\s*",
        f.text,
    ))


def _builder_code(f: IndexedFile, name: str) -> tuple[str, int] | None:
    """The code of a function named ``name`` defined in this file, string literals left out, and
    how much literal script text its strings hold (``${…}`` excluded); None if there is no such
    function."""
    n = re.escape(name)
    m = re.search(
        rf"\bfunction\s+{n}\s*\([^)]{{0,200}}\)[^{{]{{0,80}}\{{"
        rf"|\b(?:const|let|var)\s+{n}\s*=\s*(?:async\s+)?(?:function\b[^{{]{{0,200}}|"
        rf"\([^)]{{0,200}}\)[^{{]{{0,80}}=>\s*)\{{",
        f.text,
    )
    if m is None:
        return None
    code: list[str] = []
    literal = 0
    depth, i, stop = 0, m.end() - 1, min(len(f.text), m.end() + _BUILDER_BODY_CHARS)
    while i < stop:
        span = f.string_span_at(i)
        if span is not None and span[0] == i:
            literal += len(_INTERPOLATION.sub("", f.text[span[0] + 1 : span[1] - 1]).strip())
            code.append(" ")
            i = span[1]
            continue
        ch = f.text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return "".join(code), literal
        code.append(ch)
        i += 1
    return None


def _is_local_script(f: IndexedFile, at: int, depth: int = 0) -> int | None:
    """End offset of a script expression at ``at`` that this file spells out, or None.

    A string/template literal; a name every assignment of which is one; or a call to a function
    defined in the file whose body builds the text without any input (a script builder such as
    ``buildWindowsAclScript(paths)``), alone or through a name.
    """
    if depth > 2:
        return None
    text = f.text
    while at < len(text) and text[at].isspace():
        at += 1
    if at < len(text) and text[at] in "'\"`":
        span = f.string_span_at(at)
        return span[1] if span is not None and span[0] == at else None
    ident = _IDENT.match(text, at)
    if ident is None:
        return None
    end = ident.end()
    call = re.match(r"\s*\([^()]{0,200}\)", text[end : end + 210])
    if call is not None:
        builder = _builder_code(f, ident.group(0))
        if (
            builder is None
            or builder[1] < _MIN_BUILDER_SCRIPT
            or _BUILDER_IO.search(builder[0])
        ):
            return None
        return end + call.end()
    bound = _bindings(f, ident.group(0))
    if not bound or any(_is_local_script(f, b.end(), depth + 1) is None for b in bound):
        return None
    return end


def _encodes_local_script(f: IndexedFile, buffer_from_end: int) -> bool:
    """True for ``Buffer.from(<local script>, "utf16le").toString("base64")`` at that offset."""
    script_end = _is_local_script(f, buffer_from_end)
    return script_end is not None and bool(_UTF16_BASE64_TAIL.match(f.text, script_end))


def _encodes_visible_script(f: IndexedFile, flag_end: int) -> bool:
    """True if ``-EncodedCommand``'s value is a script from this file, encoded right here."""
    if f.suffix not in _JS_FAMILY:
        return False
    nxt = _NEXT_ARG.match(f.text, flag_end, flag_end + _LOOKAHEAD_CHARS)
    if nxt is None:
        return False
    if nxt.group(1):
        return _encodes_local_script(f, nxt.end(1))
    bound = _bindings(f, nxt.group(2))
    if not bound:
        return False
    for b in bound:
        encoder = re.match(r"Buffer\.from\s*\(", f.text[b.end() : b.end() + 20])
        if encoder is None or not _encodes_local_script(f, b.end() + encoder.end()):
            return False
    return True


_RULE = RuleSpec(
    id=R_SHELL_EVASION,
    category="defense_evasion",
    severity=Severity.HIGH,
    title="Defense-evasion command idiom",
    description=(
        "A command uses a known defense-evasion idiom: PowerShell execution-policy "
        "bypass / encoded command / hidden window, macOS code-signing bypass, or "
        "launching a payload from a world-writable temp directory. These are hallmarks "
        "of droppers and rarely appear in legitimate code."
    ),
    recommendation=(
        "Verify why the component bypasses execution policy / code signing or runs from a "
        "temp directory; these patterns are characteristic of malware staging."
    ),
    capability=None,
    threat_class=ThreatClass.RISKY_CONSTRUCT,
    suffixes=_EVASION_SUFFIXES,
    # A behaviour detector matches its own pattern literals in .py source; demote those.
    code_context="strings_and_comments",
    pattern=alternation(
        r"(?:-ep|-executionpolicy)\s+bypass",
        r"-encodedcommand\b",
        r"(?:powershell|pwsh)\b[^\n]{0,80}-enc\b",
        r"-windowstyle\s+hidden\b",
        r"codesign\b[^\n]*--force[^\n]*--deep",
        r"\bnohup\b(?:[^\n>]|>(?!\s*/tmp/))*\s/tmp/\S",
        r"\bchmod\s+\+x\b[^\n]*(?:/tmp/|/dev/shm/)",
        r"(?:iex|invoke-expression)\b[^\n]*"
        r"(?:downloadstring|invoke-webrequest|\biwr\b|net\.webclient)",
        flags=re.IGNORECASE,
    ),
)


class ShellEvasionScanner(Scanner):
    name = "shell_evasion"
    rules = [_RULE]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        seen: set[tuple[str, int, int]] = set()
        encoded_scripts: list[str] = []
        checks: dict[str, int] = {}
        for f, m, ev in index.search(_RULE.pattern, suffixes=_RULE.suffixes):  # type: ignore[arg-type]
            key = (ev.file, ev.line_start, ev.line_end)
            if key in seen:
                continue
            seen.add(key)
            # Each check reads the file again, so a file gets a few of them (an honest one has a
            # handful of encoded calls); past that every match is simply a finding.
            if _ENCODED_FLAG.fullmatch(m.group(0)) and checks.get(f.relpath, 0) < _MAX_CHECKS:
                checks[f.relpath] = checks.get(f.relpath, 0) + 1
                if _encodes_visible_script(f, m.end()):
                    if f.relpath not in encoded_scripts:
                        encoded_scripts.append(f.relpath)
                    continue
            evidence.append(ev)
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break
        findings = [_finding_from_rule(_RULE, evidence)] if evidence else []
        needs_review = []
        if encoded_scripts:
            needs_review.append(NeedsReview(
                category="defense_evasion",
                title="PowerShell -EncodedCommand of a script in the same file",
                reason=(
                    "PowerShell is handed a script this component spells out in clear text, "
                    "base64-encoded in place (the usual way to pass a multi-line script without "
                    f"quoting): {', '.join(encoded_scripts[:5])}. Nothing is hidden from a reader; "
                    "review the script itself."
                ),
                file=encoded_scripts[0],
            ))
        return ScanResult(findings=findings, needs_review=needs_review)
