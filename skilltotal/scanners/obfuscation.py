"""Obfuscation indicator detection.

A decode-and-execute chain (e.g. ``eval(atob(...))``) is a confirmed, evidence-backed
finding. Weaker indicators that cannot be confirmed as malicious on their own — a lone
large base64 blob, heavy hex escaping, or an extremely long (minified) line — are routed
to ``needs_review`` rather than inflating the score.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    aggregated_review,
    alternation,
    findings_from_rules,
)

CATEGORY = "obfuscation"

# The optional ``\w+\.`` prefix tolerates a module alias (``import base64 as b`` ->
# ``b.b64decode``); a method literally named ``b64decode`` is essentially always base64.
_DECODE_EXEC = alternation(
    r"exec\s*\(\s*(?:\w+\.)?b64decode",
    r"eval\s*\(\s*(?:\w+\.)?b64decode",
    r"exec\s*\(\s*bytes\.fromhex",
    r"eval\s*\(\s*bytes\.fromhex",
    r"exec\s*\(\s*codecs\.decode",
    r"eval\s*\(\s*atob\s*\(",
    # Indirect eval to dodge a literal ``eval(`` token: ``(0, eval)(atob(...))``.
    r"\(\s*0\s*,\s*eval\s*\)\s*\(\s*(?:atob|Buffer\.from)\s*\(",
    r"Function\s*\(\s*atob\s*\(",
    r"eval\s*\(\s*Buffer\.from\s*\([^)]*['\"]base64['\"]",
)

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
                "A pattern that decodes data and immediately executes it was detected "
                "(e.g. eval(atob(...)) or exec(b64decode(...)))."
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

        needs_review: list[NeedsReview] = []
        self._heuristic(index, _BASE64_BLOB, "ST-OBF-BASE64-BLOB",
                        "Large base64 blob", "large base64-looking blob(s)", needs_review)
        self._heuristic(index, _HEX_ESCAPES, "ST-OBF-HEX",
                        "Excessive hex escaping", "run(s) of hex escape sequences", needs_review)
        self._minified(index, needs_review)
        return ScanResult(findings=findings, needs_review=needs_review)

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
