"""Obfuscation indicator detection.

A decode-and-execute chain (e.g. ``eval(atob(...))``) is a confirmed, evidence-backed
finding. Weaker indicators that cannot be confirmed as malicious on their own — a lone
large base64 blob, heavy hex escaping, or an extremely long (minified) line — are routed
to ``needs_review`` rather than inflating the score.
"""

from __future__ import annotations

import bisect
import re

from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, Evidence, Finding, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    _finding_from_rule,
    aggregated_review,
    alternation,
    findings_from_rules,
)

CATEGORY = "obfuscation"

# The optional ``\w+\.`` prefix tolerates a module alias (``import base64 as b`` ->
# ``b.b64decode``); a method literally named ``b64decode`` is essentially always base64.
# A hex decoder by its usual names (`hexDecode`, `fromHex`, `hex2str`, `unhex`, ...).
_HEX_DECODER = (
    r"(?:[\w$]+\.)?(?i:hex_?decode|decode_?hex|from_?hex|unhex|"
    r"hex_?(?:2|to_?)(?:str|string|ascii|utf8|text))\s*\("
)
# What a sink may run straight from a decoder: Python's decoders, and the JavaScript ones --
# `atob`, Buffer-decoded base64 or hex (`new Function(Buffer.from(h, "hex").toString())()`), a hex
# decoder, and a string literal written entirely as escapes, which the parser decodes.
_PY_DECODE_CALL = (
    r"(?:\w+\.)?b64decode|bytes\.fromhex|codecs\.decode|(?:binascii\.)?(?:unhexlify|a2b_hex)\s*\("
)
_JS_DECODE_CALL = (
    r"atob\s*\(|Buffer\.from\s*\([^)]*['\"](?:base64|hex)['\"]|" + _HEX_DECODER
    + r"|['\"`](?:\\x[0-9A-Fa-f]{2}|\\u00[0-9A-Fa-f]{2}){8}"
)
# One alternative per sink, each starting with a literal character. That is what lets the regex
# engine skip ahead to the few places a match can begin; an alternative opening with a group such
# as `(?:eval|Function)` or with `\b` turns that off for the whole regex (it ran five to ten times
# slower over a large package), and a dozen alternatives sharing `eval(` re-test it at every `e`.
_DECODE_EXEC_ALTERNATIVES = (
    rf"exec\s*\(\s*(?:{_PY_DECODE_CALL})",
    rf"eval\s*\(\s*(?:{_PY_DECODE_CALL}|{_JS_DECODE_CALL})",
    # Indirect eval to dodge a literal ``eval(`` token: ``(0, eval)(atob(...))``.
    r"\(\s*0\s*,\s*eval\s*\)\s*\(\s*(?:atob|Buffer\.from)\s*\(",
    rf"Function\s*\(\s*(?:{_JS_DECODE_CALL})",
)
_DECODE_EXEC = alternation(*_DECODE_EXEC_ALTERNATIVES)

# The same decode and execute split over two statements: the decoded text is kept in a variable
# that eval / the Function constructor / exec then runs (`const stage = Buffer.from(h, "hex")
# .toString(); new Function(stage)()`, or `stage` assigned a literal written entirely as escapes).
# Both halves must be there, and the sink must take that very variable: a hex utility, or a
# `new Function("return this")`, is not a decode-and-execute.
_JS_DECODED_VARIABLE = re.compile(
    # Starts with the keyword itself, so the engine can skip to the letters it begins with; the
    # word boundary in front is checked in code. An optional TypeScript annotation:
    # `const stage: string = ...`.
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]{0,60})(?:\s*:\s*[\w$.<>\[\]| ]{1,40}?)?\s*=\s*(?:"
    r"Buffer\.from\s*\([^;\n]{0,200}?['\"](?:hex|base64)['\"]"
    r"|(?:window\.|globalThis\.)?atob\s*\("
    r"|" + _HEX_DECODER
    + r"|['\"`](?:\\x[0-9A-Fa-f]{2}|\\u00[0-9A-Fa-f]{2}){8}"
    r")"
)
# A code sink and the variable it runs (for the Function constructor, its last argument, the body).
# Like the regexes above, it starts with a literal; the word boundary in front is checked in code.
_JS_CODE_SINK = re.compile(
    r"(?:eval|Function|setTimeout|setInterval|vm\.runIn(?:This|New)Context|vm\.Script)"
    r"\s*\(\s*(?:[^()\n]{0,200},\s*)?([A-Za-z_$][\w$]{0,60})(?:\.toString\(\s*\))?\s*[,)]"
)
_PY_DECODED_VARIABLE = re.compile(
    r"(?m)^[ \t]*([A-Za-z_]\w{0,60})\s*=\s*(?:"
    r"bytes\.fromhex\s*\(|(?:binascii\.)?(?:unhexlify|a2b_hex)\s*\("
    r"|codecs\.decode\s*\([^)\n]{0,200}['\"]hex['\"]|(?:\w+\.)?b64decode\s*\("
    r"|[bru]{0,2}['\"](?:\\x[0-9A-Fa-f]{2}){8}"
    r")"
)
# Builtins only: `re.compile(pattern)` is not a sink, so a `.` in front rules a match out (in code).
_PY_CODE_SINK = re.compile(r"(?:exec|eval|compile)\s*\(\s*([A-Za-z_]\w{0,60})\b")
_FLOW_REACH = 4000
# Every sink above contains one of the first tokens, every decoded source one of the second.
_JS_SINK_TOKENS = ("eval", "Function", "setTimeout", "setInterval", "runIn", "Script")
_PY_SINK_TOKENS = ("exec", "eval", "compile")
_JS_SOURCE_TOKENS = ("Buffer.from", "atob", "hex", "Hex", "HEX", "\\x", "\\u00")
_PY_SOURCE_TOKENS = ("fromhex", "unhexlify", "a2b_hex", "codecs", "b64decode", "\\x")
_JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")
_PY_SUFFIXES = (".py", ".pyw")


def _starts_a_word(text: str, start: int, word_chars: str) -> bool:
    """True if nothing that continues an identifier (letters, digits, ``word_chars``) sits right
    before ``start``: `eval(` but not `myeval(`, `Function(` but not `isFunction(`."""
    if not start:
        return True
    before = text[start - 1]
    return not (before.isalnum() or before in word_chars)


def _decoded_then_executed(index: FileIndex) -> list[Evidence]:
    """Evidence for a decoded value kept in a variable and run a few statements later: the
    assignment that decodes it, then the call that executes it. Each file's sinks are indexed by
    the variable they run once, so the cost stays linear in the file."""
    evidence: list[Evidence] = []
    for f in index.select(suffixes=_JS_SUFFIXES + _PY_SUFFIXES):
        text = f.text
        if f.suffix in _PY_SUFFIXES:
            source, sink = _PY_DECODED_VARIABLE, _PY_CODE_SINK
            sinks, sources, before_sink = _PY_SINK_TOKENS, _PY_SOURCE_TOKENS, "_."
        else:
            source, sink = _JS_DECODED_VARIABLE, _JS_CODE_SINK
            sinks, sources, before_sink = _JS_SINK_TOKENS, _JS_SOURCE_TOKENS, "_$"
        # No sink or no decoder in the file: substring checks skip it before any regex runs.
        if not (any(t in text for t in sinks) and any(t in text for t in sources)):
            continue
        decoded = [m for m in source.finditer(text) if _starts_a_word(text, m.start(), "_$")]
        if not decoded:
            continue
        runs: dict[str, list[re.Match[str]]] = {}
        for run in sink.finditer(text):
            if _starts_a_word(text, run.start(), before_sink):
                runs.setdefault(run.group(1), []).append(run)
        starts = {name: [r.start() for r in found] for name, found in runs.items()}
        for m in decoded:
            found = runs.get(m.group(1))
            if not found:
                continue
            k = bisect.bisect_left(starts[m.group(1)], m.end())
            if k == len(found) or found[k].start() >= m.end() + _FLOW_REACH:
                continue
            run = found[k]
            evidence.append(f.evidence_for_span(m.start(), m.end()))
            evidence.append(f.evidence_for_span(run.start(), run.end()))
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                return evidence
    return evidence


# A decode-function name resolved dynamically instead of written as a literal attribute access,
# so the call never shows the ``exec(``/``eval(`` immediately followed by ``b64decode``/``atob``
# shape _DECODE_EXEC looks for. Reported against Claude Code / OpenAI Codex agent skills in
# September 2026: commands are "rewritten into forms that mean the same thing to a computer but
# look harmless to a scanner" (cybersecuritynews.com). Covers both a getattr()/__dict__/vars()
# lookup and the decode-function name itself split across a string concatenation.
_DYNAMIC_DECODE_NAME = (
    r"""['"]b64['"]\s*\+\s*['"]decode['"]"""
    r"""|['"]b64decode['"]"""
    r"""|['"]ato['"]\s*\+\s*['"]b['"]"""
    r"""|['"]atob['"]"""
    r"""|['"]from['"]\s*\+\s*['"]hex['"]"""
    r"""|['"]fromhex['"]"""
)
_DYNAMIC_DECODE_LOOKUP = (
    rf"getattr\s*\(\s*[\w.]+\s*,\s*(?:{_DYNAMIC_DECODE_NAME})\s*\)"
    rf"|(?:\.__dict__|\bvars\([\w.]*\))\s*\[\s*(?:{_DYNAMIC_DECODE_NAME})\s*\]"
)
_DYNAMIC_DECODE_EXEC = alternation(
    rf"exec\s*\(\s*(?:{_DYNAMIC_DECODE_LOOKUP})\s*\(",
    rf"eval\s*\(\s*(?:{_DYNAMIC_DECODE_LOOKUP})\s*\(",
)

# Symmetric decryption feeding a dynamic-code sink in the SAME file: the staged-loader shape of
# the mini "Shai-Hulud" npm compromise (Mend, August 2026), whose loader decrypts its next stage
# with AES-128-GCM and runs the plaintext through `new Function(...)`. _DECODE_EXEC only catches a
# decode call written directly inside exec(/eval(; here the ciphertext is decrypted into a
# variable first, so no single call shows the shape. Decrypting data in order to EXECUTE it (not
# to read, display or write it) keeps the payload opaque to any static reviewer until runtime —
# a strong obfuscated-execution indicator distinct from a decode-and-exec one-liner.
_DECRYPT_CONSTRUCT = re.compile(
    r"\bcreateDecipher(?:iv)?\s*\(|"              # Node: crypto.createDecipheriv(...)
    r"\bsubtle\s*\.\s*decrypt\s*\(|"              # WebCrypto: crypto.subtle.decrypt(...)
    r"\bAES\s*\.\s*new\s*\([^)]*\)\s*\.\s*decrypt\b|"  # PyCryptodome: AES.new(...).decrypt(...)
    r"\bFernet\s*\([^)]*\)\s*\.\s*decrypt\b"      # cryptography.Fernet(...).decrypt(...)
)
# Dynamic-code sinks. `.exec(`/`child_process.exec` are command execution, not a code sink, so
# the method-form and the bare `exec(` token are deliberately excluded (the negative lookbehind
# drops `.eval`); `eval(`/`new Function(` are code sinks in both JS and Python.
_EXEC_SINK = re.compile(
    r"\bnew\s+Function\s*\(|"
    r"\bvm\s*\.\s*(?:runInThisContext|runInContext|runInNewContext|compileFunction)\s*\(|"
    r"\bnew\s+vm\s*\.\s*Script\s*\(|"
    r"(?<![\w.])eval\s*\("
)
_DECRYPT_EXEC_SUFFIXES = (".py", ".pyw", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{160,}={0,2}")
_HEX_ESCAPES = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){10,}")
_MINIFIED_LINE_CHARS = 2000

# Build artifacts where a single very long line is the *expected* format, not an
# obfuscation signal: source maps (single-line JSON), pre-minified bundles, TypeScript
# declaration files, and lockfiles. Other rules still scan these files normally — only
# the minified-line note skips them.
_EXPECTED_LONG_LINE_SUFFIXES = (
    ".map", ".min.js", ".min.mjs", ".min.cjs", ".min.css",
    ".d.ts", ".d.mts", ".d.cts",
)
_EXPECTED_LONG_LINE_NAMES = {"package-lock.json"}
_MINIFIED_EXAMPLES_SHOWN = 8


def _is_expected_long_line_file(relpath: str) -> bool:
    name = relpath.rsplit("/", 1)[-1].lower()
    return name in _EXPECTED_LONG_LINE_NAMES or name.endswith(_EXPECTED_LONG_LINE_SUFFIXES)


class ObfuscationScanner(Scanner):
    name = "obfuscation"
    rules = [
        RuleSpec(
            id="ST-OBF-DECODE-EXEC",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Decode-and-execute (obfuscated execution)",
            description=(
                "A pattern that decodes data and executes it was detected "
                "(e.g. eval(atob(...)), new Function(Buffer.from(x, 'hex').toString()) or "
                "exec(b64decode(...)), directly or through a variable that holds the decoded text)."
            ),
            recommendation=(
                "Decoding and executing data hides behavior from review. Decode the payload "
                "manually and inspect what it does before trusting this component."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            # A real decode-and-exec is code; the same text inside a string or comment -- in ANY
            # language -- is a pattern literal, a doc example or another scanner's message, not
            # behavior. Unlike a credential path, `eval(atob(...))` inside a string literal can
            # never execute, so the C-family string demotion (`_all`) is safe here: a `demos.js`
            # carrying `description: 'eval(atob("…"))'` and a security auditor listing the pattern
            # in a message both scored as obfuscated execution without it.
            code_context="strings_and_comments_all",
            pattern=_DECODE_EXEC,
        ),
        RuleSpec(
            id="ST-OBF-DYNAMIC-DECODE-EXEC",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Dynamically-resolved decode-and-execute (scanner-evasion variant)",
            description=(
                "A decode function (b64decode/atob/fromhex) is resolved through getattr(), "
                "__dict__ or vars() instead of a literal attribute, and the result is "
                "immediately executed. This evades a plain decode-exec scanner, which looks for "
                "the function name written right after exec(/eval(."
            ),
            recommendation=(
                "Decode the payload manually and inspect what it does before trusting this "
                "component. Resolving a decode function dynamically has no honest purpose here; "
                "it exists to dodge static scanners."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            # Same reasoning as ST-OBF-DECODE-EXEC: a match inside a string/comment is a pattern
            # literal or doc example, never live behavior.
            code_context="strings_and_comments_all",
            pattern=_DYNAMIC_DECODE_EXEC,
        ),
        RuleSpec(
            id="ST-OBF-DECRYPT-EXEC",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Decrypt-and-execute (encrypted payload run at runtime)",
            description=(
                "A file decrypts data with a symmetric cipher (e.g. AES via "
                "crypto.createDecipheriv / PyCryptodome / Fernet) and, in the same file, feeds "
                "code to a dynamic-execution sink (new Function / eval / vm.runInThisContext). "
                "Decrypting a payload in order to run it keeps the real behavior opaque to static "
                "review until runtime — the staged-loader shape seen in the August 2026 "
                "'mini Shai-Hulud' npm compromise."
            ),
            recommendation=(
                "Decrypt the payload offline and inspect what it does before trusting this "
                "component. Running encrypted code at runtime has no honest purpose that cannot "
                "be met by shipping the code in the clear."
            ),
            capability=Capability.DYNAMIC_CODE_EXECUTION,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
            # A match inside a string/comment is a pattern literal or doc example, never live
            # behavior — same reasoning as ST-OBF-DECODE-EXEC.
            code_context="strings_and_comments_all",
        ),
        # The following are listed for `rules list`; they emit needs_review only.
        RuleSpec(
            id="ST-OBF-BASE64-BLOB",
            category=CATEGORY,
            severity=Severity.LOW,
            title="Large base64 blob",
            description="A large base64-looking blob was detected.",
            recommendation="Decode and inspect the blob to confirm it is benign data.",
            capability=None,
        ),
        RuleSpec(
            id="ST-OBF-HEX",
            category=CATEGORY,
            severity=Severity.LOW,
            title="Excessive hex escaping",
            description="A run of many hex escape sequences was detected.",
            recommendation="Decode the escaped sequence to confirm intent.",
            capability=None,
        ),
        RuleSpec(
            id="ST-OBF-MINIFIED",
            category=CATEGORY,
            severity=Severity.LOW,
            title="Heavily minified / very long line",
            description="A file contains an extremely long line (possible minification).",
            recommendation="Review whether the file should be minified in source form.",
            capability=None,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        scored_ids = {"ST-OBF-DECODE-EXEC", "ST-OBF-DYNAMIC-DECODE-EXEC"}
        findings = findings_from_rules(index, [r for r in self.rules if r.id in scored_ids])
        flow = _decoded_then_executed(index)
        if flow:
            rule = self.rules[0]
            direct = next((f for f in findings if f.id == rule.id), None)
            seen: set[tuple[str, int, int]] = set()
            evidence: list[Evidence] = []
            for ev in [*(direct.evidence if direct else ()), *flow]:
                if (ev.file, ev.line_start, ev.line_end) not in seen:
                    seen.add((ev.file, ev.line_start, ev.line_end))
                    evidence.append(ev)
            findings = [f for f in findings if f.id != rule.id]
            findings.insert(0, _finding_from_rule(rule, evidence[:MAX_EVIDENCE_SCANNED]))

        decrypt_exec = self._decrypt_exec(index)
        if decrypt_exec:
            rule = next(r for r in self.rules if r.id == "ST-OBF-DECRYPT-EXEC")
            findings.append(
                Finding(
                    id=rule.id, severity=rule.severity, category=rule.category,
                    title=rule.title, description=rule.description,
                    evidence=decrypt_exec[:MAX_EVIDENCE_SCANNED],
                    recommendation=rule.recommendation,
                    threat_class=rule.threat_class,
                )
            )

        needs_review: list[NeedsReview] = []
        self._heuristic(index, _BASE64_BLOB, "ST-OBF-BASE64-BLOB",
                        "Large base64 blob", "large base64-looking blob(s)", needs_review)
        self._heuristic(index, _HEX_ESCAPES, "ST-OBF-HEX",
                        "Excessive hex escaping", "run(s) of hex escape sequences", needs_review)
        self._minified(index, needs_review)
        return ScanResult(findings=findings, needs_review=needs_review)

    @staticmethod
    def _decrypt_exec(index: FileIndex) -> list[Evidence]:
        """Evidence when one code file both decrypts data and runs code through a dynamic sink.

        Requires BOTH signals in the same file (the staged loader decrypts, then executes the
        plaintext). Engine-level string/comment demotion (code_context) drops matches that are
        only pattern literals or doc examples, so a security tool listing these patterns in a
        message is not flagged.
        """
        evidence: list[Evidence] = []
        for f in index.select(suffixes=_DECRYPT_EXEC_SUFFIXES):
            dec = _DECRYPT_CONSTRUCT.search(f.text)
            sink = _EXEC_SINK.search(f.text)
            if not dec or not sink:
                continue
            evidence.append(f.evidence_for_span(dec.start(), dec.end()))
            evidence.append(f.evidence_for_span(sink.start(), sink.end()))
            if len(evidence) >= MAX_EVIDENCE_SCANNED:
                break
        return evidence

    def _heuristic(self, index, pattern, _rule_id, title, what, needs_review) -> None:
        """One aggregated note per heuristic (it used to be one per line, up to 75)."""
        places: list[tuple[str, int | None]] = []
        seen: set[tuple[str, int]] = set()
        capped = False
        for _f, _m, ev in index.search(pattern):
            key = (ev.file, ev.line_start)
            if key in seen:
                continue
            if len(places) >= MAX_EVIDENCE_SCANNED:
                capped = True
                break
            seen.add(key)
            places.append(key)
        if places:
            needs_review.append(aggregated_review(
                category=CATEGORY,
                title=title,
                places=places,
                what=what,
                advice="Malicious intent cannot be confirmed without decoding them.",
                capped=capped,
            ))

    def _minified(self, index: FileIndex, needs_review: list[NeedsReview]) -> None:
        """One aggregated note per report (not per file), skipping expected formats.

        Source maps / .d.ts / lockfiles are long-line *by design*; flagging each one
        floods a legitimate SDK's report with dozens of identical rows. Files that
        remain are summarized in a single entry listing a few examples.
        """
        minified: list[str] = []
        for f in index.files:
            if _is_expected_long_line_file(f.relpath):
                continue
            if any(len(line) > _MINIFIED_LINE_CHARS for line in f.text.splitlines()):
                minified.append(f.relpath)
        if not minified:
            return
        examples = ", ".join(minified[:_MINIFIED_EXAMPLES_SHOWN])
        more = len(minified) - _MINIFIED_EXAMPLES_SHOWN
        if more > 0:
            examples += f", and {more} more"
        needs_review.append(
            NeedsReview(
                category=CATEGORY,
                title=f"Heavily minified files ({len(minified)})",
                reason=(
                    f"{len(minified)} file(s) contain lines over {_MINIFIED_LINE_CHARS} "
                    f"characters (possible minification); not analyzable line-by-line: "
                    f"{examples}."
                ),
                file=minified[0],
            )
        )
