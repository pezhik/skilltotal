"""Hidden / invisible Unicode detection (ASCII smuggling, Trojan Source, zero-width).

Attackers hide instructions from human reviewers while keeping them readable by an LLM using
invisible code points. We split these by how unambiguous the malice is:

* **Tag characters** (U+E0000+ascii) literally encode invisible ASCII and have *no*
  legitimate use — a confirmed malicious indicator; the smuggled ASCII is decoded into the
  evidence. The one exception is a valid *emoji tag sequence* (UTS #51): U+1F3F4 BLACK FLAG
  followed by a short lowercase/digit tag run terminated by U+E007F CANCEL TAG — subdivision
  flags like 🏴+gbeng+CANCEL (England). Those are stripped before the check; any other tag
  character still fires.
* **Bidi overrides** (Trojan Source) and **zero-width** characters DO appear legitimately —
  RTL-language locale/`.po` files, CJK text, HTML-entity tables (e.g. webpack's
  ``&zwsp;``→U+200B map), emoji ZWJ sequences. On their own they are ambiguous, so they are
  routed to ``needs_review`` (surfaced, never scored) rather than raising a malware verdict.

Evidence renders invisible characters as ``<U+XXXX>`` so they are visible in the report.
"""

from __future__ import annotations

import re

from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, Evidence, Finding, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import MAX_EVIDENCE_PER_FINDING, RuleSpec, Scanner, ScanResult

CATEGORY = "hidden_unicode"

# Ambiguous (legitimate in i18n / RTL / CJK / HTML-entity tables / emoji) -> needs_review:
# bidi overrides + isolates, zero-width space/joiner/non-joiner/word-joiner, soft hyphen, BOM.
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))
_ZERO_WIDTH = {0x200B, 0x2060, 0x200C, 0x200D, 0x00AD, 0xFEFF}
_REVIEW = _BIDI | _ZERO_WIDTH


# Valid emoji tag sequence (UTS #51): U+1F3F4 base + 1-8 tag lowercase/digit chars + CANCEL TAG.
# Unicode's own data files (emoji-test.txt, shipped by terminal/width libraries) contain these,
# so they must not count as smuggling. The 8-char cap keeps the exempt channel negligible: an
# attacker can hide at most a flag-shaped 8-char lowercase run per visible black flag.
_EMOJI_TAG_SEQ = re.compile(
    "\U0001F3F4[\U000E0030-\U000E0039\U000E0061-\U000E007A]{1,8}\U000E007F"
)


def _is_tag(cp: int) -> bool:
    return 0xE0000 <= cp <= 0xE007F


def _is_review(cp: int) -> bool:
    return cp in _REVIEW


def _decode_tags(line: str) -> str:
    """Decode Unicode tag characters in a line back to the ASCII they smuggle."""
    out = []
    for ch in line:
        cp = ord(ch)
        if _is_tag(cp):
            out.append(chr(cp - 0xE0000))
    decoded = "".join(out)
    return "".join(c for c in decoded if c.isprintable())


def _render(line: str) -> str:
    return "".join(c if not (_is_tag(ord(c)) or _is_review(ord(c)))
                   else f"<U+{ord(c):04X}>" for c in line)


class InvisibleUnicodeScanner(Scanner):
    name = "invisible_unicode"
    rules = [
        RuleSpec(
            id="ST-HIDDEN-UNICODE",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Hidden / invisible Unicode (ASCII smuggling)",
            description=(
                "Unicode tag characters (U+E0000+) were detected — invisible code points that "
                "encode ASCII. They have no legitimate use and are used to smuggle "
                "instructions past human review while remaining readable by an LLM."
            ),
            recommendation=(
                "Treat the component as malicious until reviewed. Inspect the decoded hidden "
                "text; legitimate AI components do not hide instructions in invisible Unicode."
            ),
            capability=Capability.PROMPT_SURFACE_RISK,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
        RuleSpec(
            id="ST-HIDDEN-UNICODE-AMBIG",
            category=CATEGORY,
            severity=Severity.LOW,
            title="Bidi / zero-width Unicode",
            description=(
                "Bidirectional overrides or zero-width characters were detected. These can be "
                "used to hide text (Trojan Source), but also appear legitimately in RTL-locale "
                "files, CJK text, HTML-entity tables, and emoji — so they are flagged for "
                "review rather than scored."
            ),
            recommendation="Confirm the characters are part of legitimate text (locale/script).",
            capability=None,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        needs_review: list[NeedsReview] = []
        review_seen: set[str] = set()

        for f in index.files:
            # Every character this scanner hunts (tag chars, bidi controls, zero-width) is
            # non-ASCII, so a pure-ASCII file cannot contain any. One C-speed check skips the
            # per-line/per-char Python loops below for the overwhelmingly common case.
            if f.text.isascii():
                continue
            for lineno, raw_line in enumerate(f.text.splitlines(), start=1):
                # Strip valid emoji tag sequences (subdivision flags) so the tag-character
                # check below only sees tag chars with no legitimate reading.
                line = (_EMOJI_TAG_SEQ.sub("", raw_line)
                        if "\U0001F3F4" in raw_line else raw_line)
                tags = [c for c in line if _is_tag(ord(c))]
                if tags:
                    snippet = _render(line)[:200]
                    decoded = _decode_tags(line)
                    if decoded:
                        snippet += f"  [decoded hidden text: {decoded[:120]!r}]"
                    if len(evidence) < MAX_EVIDENCE_PER_FINDING:
                        evidence.append(
                            Evidence(file=f.relpath, line_start=lineno, line_end=lineno,
                                     snippet=snippet)
                        )
                elif any(_is_review(ord(c)) for c in line) and f.relpath not in review_seen:
                    review_seen.add(f.relpath)
                    needs_review.append(
                        NeedsReview(
                            category=CATEGORY,
                            title="Bidi / zero-width Unicode",
                            reason=(
                                f"Bidi/zero-width character(s) at line {lineno} may be "
                                "legitimate (locale/RTL/CJK/HTML entities) but can also hide "
                                "text; review the rendered characters."
                            ),
                            file=f.relpath,
                            line=lineno,
                        )
                    )

        findings: list[Finding] = []
        if evidence:
            rule = self.rules[0]
            findings.append(
                Finding(
                    id=rule.id, severity=rule.severity, category=rule.category,
                    title=rule.title, description=rule.description,
                    evidence=evidence, recommendation=rule.recommendation,
                )
            )
        return ScanResult(findings=findings, needs_review=needs_review)
