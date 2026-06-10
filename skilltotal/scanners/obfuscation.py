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
    MAX_EVIDENCE_PER_FINDING,
    RuleSpec,
    Scanner,
    ScanResult,
    alternation,
    findings_from_rules,
)

CATEGORY = "obfuscation"

_DECODE_EXEC = alternation(
    r"exec\s*\(\s*(?:base64\.)?b64decode",
    r"eval\s*\(\s*(?:base64\.)?b64decode",
    r"exec\s*\(\s*bytes\.fromhex",
    r"eval\s*\(\s*bytes\.fromhex",
    r"exec\s*\(\s*codecs\.decode",
    r"eval\s*\(\s*atob\s*\(",
    r"Function\s*\(\s*atob\s*\(",
    r"eval\s*\(\s*Buffer\.from\s*\([^)]*['\"]base64['\"]",
)

_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{160,}={0,2}")
_HEX_ESCAPES = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){10,}")
_MINIFIED_LINE_CHARS = 2000


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
            pattern=_DECODE_EXEC,
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
        findings = findings_from_rules(index, [self.rules[0]])

        needs_review: list[NeedsReview] = []
        self._heuristic(index, _BASE64_BLOB, "ST-OBF-BASE64-BLOB",
                        "Large base64 blob", "large base64-looking blob", needs_review)
        self._heuristic(index, _HEX_ESCAPES, "ST-OBF-HEX",
                        "Excessive hex escaping", "run of hex escape sequences", needs_review)
        self._minified(index, needs_review)
        return ScanResult(findings=findings, needs_review=needs_review)

    def _heuristic(self, index, pattern, _rule_id, title, what, needs_review) -> None:
        seen: set[tuple[str, int]] = set()
        for _f, _m, ev in index.search(pattern):
            key = (ev.file, ev.line_start)
            if key in seen:
                continue
            seen.add(key)
            needs_review.append(
                NeedsReview(
                    category=CATEGORY,
                    title=title,
                    reason=(
                        f"A {what} was found at line {ev.line_start}; cannot confirm "
                        "malicious intent without decoding."
                    ),
                    file=ev.file,
                    line=ev.line_start,
                )
            )
            if len(needs_review) >= 3 * MAX_EVIDENCE_PER_FINDING:
                return

    def _minified(self, index: FileIndex, needs_review: list[NeedsReview]) -> None:
        for f in index.files:
            for lineno, line in enumerate(f.text.splitlines(), start=1):
                if len(line) > _MINIFIED_LINE_CHARS:
                    needs_review.append(
                        NeedsReview(
                            category=CATEGORY,
                            title="Heavily minified / very long line",
                            reason=(
                                f"Contains a line of {len(line)} characters (possible "
                                "minification); not analyzable line-by-line."
                            ),
                            file=f.relpath,
                            line=lineno,
                        )
                    )
                    break  # one note per file is enough
