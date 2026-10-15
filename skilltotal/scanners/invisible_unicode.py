"""Hidden / invisible Unicode detection (ASCII smuggling, Trojan Source, zero-width).

Attackers hide instructions from human reviewers while keeping them readable by an LLM using
invisible code points. We split these by how unambiguous the malice is:

* **Tag characters** (U+E0000+ascii) literally encode invisible ASCII and have *no*
  legitimate use — a confirmed malicious indicator; the smuggled ASCII is decoded into the
  evidence. The one exception is a valid *emoji tag sequence* (UTS #51): U+1F3F4 BLACK FLAG
  followed by a short lowercase/digit tag run terminated by U+E007F CANCEL TAG — subdivision
  flags like 🏴+gbeng+CANCEL (England). Those are stripped before the check; any other tag
  character still fires.
* **Variation selectors** (U+FE00-FE0F, U+E0100-E01EF) carry one byte each (Paul Butler, 2025):
  a run of them after one visible character is an invisible payload, decoded into the evidence.
  A run of four or more, or a supplementary selector after anything but a CJK ideograph (where
  registered ideographic variation sequences use it), has no legitimate reading. A single
  U+FE0F after an emoji is ordinary emoji presentation.
* **Invisible math operators** (U+2061-U+2064, "Sneaky Bits"): a run of four or more is an
  encoding, binary when only U+2062 (0) and U+2064 (1) are used; that binary is decoded.
* **Hangul fillers** (U+115F, U+1160, U+3164, U+FFA0) are valid JavaScript identifier letters
  that render as nothing: one used as a variable or parameter outside a string or comment is an
  invisible identifier (the "invisible backdoor" shape).
* **Bidi overrides** (Trojan Source) and **zero-width** characters DO appear legitimately —
  RTL-language locale/`.po` files, CJK text, HTML-entity tables (e.g. webpack's
  ``&zwsp;``→U+200B map), emoji ZWJ sequences. On their own they are ambiguous, so they are
  routed to ``needs_review`` (surfaced, never scored) rather than raising a malware verdict.
* **ANSI escape sequences** in text an agent reads (an instruction file such as ``SKILL.md``, an
  MCP tool description or server ``instructions``): concealment, cursor movement and line or
  screen erasure hide text from a person reading it in a terminal -> ``ST-HIDDEN-ANSI``. Other
  ANSI there (colors) is only noted for review; ANSI in ordinary source, logs and tests is not
  looked at.

Evidence renders invisible characters as ``<U+XXXX>`` so they are visible in the report.
"""

from __future__ import annotations

import re
from dataclasses import replace

from skilltotal.file_index import FileIndex, IndexedFile, _c_code_spans, is_instruction_path
from skilltotal.models import Capability, Evidence, Finding, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import (
    MAX_EVIDENCE_SCANNED,
    RuleSpec,
    Scanner,
    ScanResult,
    aggregated_review,
)
from skilltotal.scanners.mcp import exposes_mcp_surface

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


# Zero-width characters threaded between the letters of ASCII words ("r<ZWSP>e<ZWSP>a<ZWSP>d").
# Emoji ZWJ sequences, CJK text and RTL scripts never put them between Latin letters, and a word
# broken this way reads to a person as nothing at all. TrapDoor (2026) hid CLAUDE.md and
# .cursorrules directives like this. Soft hyphen is excluded: it is real hyphenation.
_SPLICE = re.compile("[A-Za-z][\u200b\u200c\u200d\u2060\ufeff]+(?=[A-Za-z])")
_SPLICES_PER_LINE = 6


# Variation selectors as a byte channel: U+FE00-FE0F carry 0..15, U+E0100-E01EF carry 16..255.
_VS_RUN = re.compile("[\ufe00-\ufe0f\U000E0100-\U000E01EF]+")
_VS_PAYLOAD_RUN = 4
# Bases of registered ideographic variation sequences (CJK unified/compatibility ideographs).
_CJK_RANGES = ((0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xF900, 0xFAFF), (0x20000, 0x3134F))
# Invisible math operators: function application, invisible times / separator / plus.
_OP_RUN = re.compile("[\u2061-\u2064]{4,}")
_OP_ZERO, _OP_ONE = "\u2062", "\u2064"
# Hangul fillers: letters that render as blank space and are legal in a JavaScript identifier.
_HANGUL_FILLER = re.compile("[\u115f\u1160\u3164\uffa0]")
_JS_SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx")
_INVISIBLE_EXTRA = (
    {0x2061, 0x2062, 0x2063, 0x2064, 0x115F, 0x1160, 0x3164, 0xFFA0} | set(range(0xFE00, 0xFE10))
)


# Every code point the per-line pass acts on, as one character class: a file or a line without
# any of them cannot yield evidence or a review, so one C-speed search replaces the
# per-character Python loops below. Built from the same sets, so the two can't drift apart.
_HUNTED = re.compile(
    "[\U000E0000-\U000E007F\U000E0100-\U000E01EF\ufe00-\ufe0f\u2061-\u2064"
    + "".join(chr(cp) for cp in sorted(_REVIEW)) + "]"
)


# ANSI CSI sequences, with ESC written raw or spelled as a source escape (\u001b, \x1b, \033).
_ANSI_CSI = re.compile(r"(?:\x1b|\\(?:u001[bB]|x1[bB]|033))\[([0-9;?]*)([@-~])")
# Final bytes that move the cursor or erase the line/screen: text written before is overdrawn.
_ANSI_HIDING_FINALS = frozenset("ABCDEFGHJKf")
# A string literal that is a tool/server description: `description: "..."`, `instructions=`,
# or the second argument of `server.tool("name", "...")`.
_DESCRIPTION_KEY = re.compile(r"""\b(?:description|instructions)['"]?\s*[:=]\s*$""")
_TOOL_DESCRIPTION_ARG = re.compile(r"""\.tool\s*\(\s*(['"`])[\w.-]+\1\s*,\s*$""")
_JSON_DESCRIPTION = re.compile(r'"(?:description|instructions)"\s*:\s*"((?:\\.|[^"\\])*)"')
_CODE_SUFFIXES = (".py", ".pyw", *_JS_SUFFIXES)


def _is_tag(cp: int) -> bool:
    return 0xE0000 <= cp <= 0xE007F


def _is_review(cp: int) -> bool:
    return cp in _REVIEW


def _is_invisible(cp: int) -> bool:
    return _is_tag(cp) or _is_review(cp) or cp in _INVISIBLE_EXTRA or 0xE0100 <= cp <= 0xE01EF


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
    return "".join(f"<U+{ord(c):04X}>" if _is_invisible(ord(c)) else c for c in line)


def _printable(data: bytes) -> str:
    return "".join(c for c in data.decode("utf-8", errors="replace") if c.isprintable())


def _is_cjk_ideograph(ch: str) -> bool:
    return bool(ch) and any(lo <= ord(ch) <= hi for lo, hi in _CJK_RANGES)


def _hidden_runs(line: str) -> list[str] | None:
    """Text decoded from the variation-selector and invisible-operator runs on ``line``.

    None when the line holds no such run; a run that decodes to nothing printable adds "".
    """
    decoded: list[str] = []
    found = False
    for m in _VS_RUN.finditer(line):
        run = m.group()
        supplementary = any(ord(c) >= 0xE0100 for c in run)
        base = line[m.start() - 1] if m.start() else ""
        if len(run) < _VS_PAYLOAD_RUN and not (supplementary and not _is_cjk_ideograph(base)):
            continue  # emoji presentation (U+FE0F), a standardized or an ideographic sequence
        after = line[m.end():m.end() + 1]
        if len(run) < _VS_PAYLOAD_RUN and "-" in (base, after):
            continue  # a range end in a character table (`[︀-️...]`), no payload
        found = True
        decoded.append(_printable(bytes(
            ord(c) - 0xFE00 if ord(c) <= 0xFE0F else ord(c) - 0xE0100 + 16 for c in run
        )))
    for m in _OP_RUN.finditer(line):
        run = m.group()
        found = True
        if len(run) >= 8 and set(run) <= {_OP_ZERO, _OP_ONE}:
            bits = "".join("1" if c == _OP_ONE else "0" for c in run)
            decoded.append(_printable(bytes(
                int(bits[i:i + 8], 2) for i in range(0, len(bits) - 7, 8)
            )))
    return decoded if found else None


def _hangul_identifier_evidence(f: IndexedFile) -> list[Evidence]:
    """Hangul fillers used as identifiers in JavaScript/TypeScript code (not in text)."""
    if not f.relpath.lower().endswith(_JS_SUFFIXES) or not _HANGUL_FILLER.search(f.text):
        return []
    text_spans: list[tuple[int, int]] | None = None
    if f.suffix in (".mts", ".cts"):  # TypeScript module files: the lexical syntax of .ts
        comments, strings, regexes = _c_code_spans(f.text, ".ts")
        text_spans = comments + strings + regexes
    found: list[Evidence] = []
    lines: set[int] = set()
    for m in _HANGUL_FILLER.finditer(f.text):
        o = m.start()
        if text_spans is not None:
            if any(s <= o < e for s, e in text_spans):
                continue
        elif (f.in_c_string(o) or f.in_c_comment(o) or f.in_js_regex(o)
              or f.in_rendered_markup_text(o)):
            continue  # text, a comment or a pattern: Korean prose may hold a filler
        ev = f.evidence_for_span(o, m.end())
        if ev.line_start in lines:
            continue
        lines.add(ev.line_start)
        snippet = _render(f.line_text(ev.line_start).strip())[:200]
        found.append(replace(ev, snippet=snippet + "  [Hangul filler used as an identifier]"))
    return found


def _ansi_hides(params: str, final: str) -> bool:
    """Concealment (SGR 8), cursor movement, or line/screen erasure."""
    return final in _ANSI_HIDING_FINALS or (final == "m" and "8" in params.split(";"))


def _in_json_description(f: IndexedFile, offset: int) -> bool:
    """True if ``offset`` is inside a JSON ``"description"`` / ``"instructions"`` value."""
    line_start = f.text.rfind("\n", 0, offset) + 1
    line_end = f.text.find("\n", offset)
    line = f.text[line_start:line_end if line_end >= 0 else len(f.text)]
    return any(
        line_start + m.start(1) <= offset < line_start + m.end(1)
        for m in _JSON_DESCRIPTION.finditer(line)
    )


def _in_code_description(f: IndexedFile, offset: int) -> bool:
    """True if ``offset`` is inside a string an MCP client hands to the model."""
    if f.in_agent_facing_string(offset):
        return True
    span = f.string_span_at(offset)
    if span is None:
        return False
    head = f.text[max(0, span[0] - 120):span[0]]
    return bool(_DESCRIPTION_KEY.search(head) or _TOOL_DESCRIPTION_ARG.search(head))


def _ansi_context(f: IndexedFile, offset: int, mcp_code: bool) -> str | None:
    """Where an ANSI sequence sits: "agent" text, an "example" in an instruction file, or None."""
    if is_instruction_path(f.relpath):
        if f.suffix in (".md", ".mdx") and not f.in_markdown_prose(offset):
            return "example"  # a fenced code block in a skill: a snippet it shows, not its text
        return "agent"
    if f.suffix == ".json":
        return "agent" if _in_json_description(f, offset) else None
    if mcp_code and _in_code_description(f, offset):
        return "agent"
    return None


class InvisibleUnicodeScanner(Scanner):
    name = "invisible_unicode"
    rules = [
        RuleSpec(
            id="ST-HIDDEN-UNICODE",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Hidden / invisible Unicode (ASCII smuggling)",
            description=(
                "Invisible characters that encode or hide text were detected: Unicode tag "
                "characters (U+E0000+), zero-width characters threaded between the letters of "
                "words, runs of variation selectors or invisible math operators (each carries "
                "bits of a hidden payload), or Hangul filler letters used as invisible "
                "JavaScript identifiers. All of them hide text or code from a person while a "
                "model or interpreter still reads it, and none has a legitimate use in that "
                "form."
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
                "files, CJK text, HTML-entity tables, and emoji - so they are flagged for "
                "review rather than scored."
            ),
            recommendation="Confirm the characters are part of legitimate text (locale/script).",
            capability=None,
        ),
        RuleSpec(
            id="ST-HIDDEN-ANSI",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="ANSI escape sequence hides agent-facing text",
            description=(
                "Text an agent reads (an instruction file such as SKILL.md or CLAUDE.md, an MCP "
                "tool description, or MCP server instructions) carries an ANSI escape sequence "
                "that conceals text, moves the cursor or erases the line. Shown in a terminal, "
                "the text around it is hidden or overwritten for the person, while the model "
                "still reads all of it."
            ),
            recommendation=(
                "Treat the component as malicious until reviewed. Read the raw text with the "
                "escape sequences shown; agent instructions and tool descriptions have no "
                "reason to control a terminal."
            ),
            capability=Capability.PROMPT_SURFACE_RISK,
            threat_class=ThreatClass.MALICIOUS_INDICATOR,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        ansi_evidence: list[Evidence] = []
        needs_review: list[NeedsReview] = []
        review_seen: set[str] = set()
        review_places: list[tuple[str, int | None]] = []
        ansi_places: list[tuple[str, int | None]] = []

        for f in index.files:
            self._scan_ansi(f, ansi_evidence, ansi_places)
            # Every character this scanner hunts (tag chars, bidi controls, zero-width) is
            # non-ASCII, so a pure-ASCII file cannot contain any. One C-speed check skips the
            # per-line/per-char Python loops below for the overwhelmingly common case.
            if f.text.isascii():
                continue
            for ev in _hangul_identifier_evidence(f):
                if len(evidence) < MAX_EVIDENCE_SCANNED:
                    evidence.append(ev)
            if not _HUNTED.search(f.text):
                continue
            for lineno, raw_line in enumerate(f.text.splitlines(), start=1):
                if not _HUNTED.search(raw_line):
                    continue  # nothing this scanner acts on (most lines of a CJK document)
                # Strip valid emoji tag sequences (subdivision flags) so the tag-character
                # check below only sees tag chars with no legitimate reading.
                line = (_EMOJI_TAG_SEQ.sub("", raw_line)
                        if "\U0001F3F4" in raw_line else raw_line)
                tags = [c for c in line if _is_tag(ord(c))]
                runs = _hidden_runs(line)
                splices = len(_SPLICE.findall(line))
                if splices >= _SPLICES_PER_LINE and not tags and runs is None:
                    if len(evidence) < MAX_EVIDENCE_SCANNED:
                        hidden = "".join(c for c in line if not _is_review(ord(c)))
                        evidence.append(
                            Evidence(file=f.relpath, line_start=lineno, line_end=lineno,
                                     snippet=_render(line)[:200]
                                     + f"  [text without zero-width: {hidden[:120]!r}]")
                        )
                    continue
                if tags or runs is not None:
                    snippet = _render(line)[:200]
                    decoded = _decode_tags(line) + "".join(runs or [])
                    if decoded:
                        snippet += f"  [decoded hidden text: {decoded[:120]!r}]"
                    if len(evidence) < MAX_EVIDENCE_SCANNED:
                        evidence.append(
                            Evidence(file=f.relpath, line_start=lineno, line_end=lineno,
                                     snippet=snippet)
                        )
                elif any(_is_review(ord(c)) for c in line) and f.relpath not in review_seen:
                    review_seen.add(f.relpath)
                    review_places.append((f.relpath, lineno))

        if review_places:
            # One note for every file with ambiguous characters, not one per file.
            needs_review.append(aggregated_review(
                category=CATEGORY,
                title="Bidi / zero-width Unicode",
                places=review_places,
                what="file(s) with bidi/zero-width characters",
                advice="They may be legitimate (locale/RTL/CJK/HTML entities) but can also "
                       "hide text; review the rendered characters.",
            ))
        if ansi_places:
            needs_review.append(aggregated_review(
                category=CATEGORY,
                title="ANSI escape codes in agent-facing text",
                places=ansi_places,
                what="place(s) in agent-facing text with ANSI escape codes (colors, or a "
                     "code example)",
                advice="Usually formatting, but a model reads text that a terminal may "
                       "render differently; review the raw text.",
            ))

        findings: list[Finding] = []
        for rule, found in ((self.rules[0], evidence), (self.rules[2], ansi_evidence)):
            if found:
                findings.append(
                    Finding(
                        id=rule.id, severity=rule.severity, category=rule.category,
                        title=rule.title, description=rule.description,
                        evidence=found, recommendation=rule.recommendation,
                    )
                )
        return ScanResult(findings=findings, needs_review=needs_review)

    @staticmethod
    def _scan_ansi(
        f: IndexedFile,
        evidence: list[Evidence],
        review_places: list[tuple[str, int | None]],
    ) -> None:
        """ANSI escape sequences in text an agent reads (see the module docstring)."""
        if not _ANSI_CSI.search(f.text):
            return
        lower = f.relpath.lower()
        mcp_code = lower.endswith(_CODE_SUFFIXES) and exposes_mcp_surface(f.text)
        if not (mcp_code or lower.endswith(".json") or is_instruction_path(f.relpath)):
            return
        hiding_lines: set[int] = set()
        noted = False
        for m in _ANSI_CSI.finditer(f.text):
            context = _ansi_context(f, m.start(), mcp_code)
            if context is None:
                continue
            if context == "agent" and _ansi_hides(m.group(1), m.group(2)):
                ev = f.evidence_for_span(m.start(), m.end())
                if ev.line_start not in hiding_lines and len(evidence) < MAX_EVIDENCE_SCANNED:
                    hiding_lines.add(ev.line_start)
                    evidence.append(ev)
            elif not noted:
                noted = True
                review_places.append((f.relpath, f.line_of_offset(m.start())))
