"""Hidden / invisible Unicode detection (ASCII smuggling, Trojan Source, zero-width).

Attackers hide instructions from human reviewers while keeping them readable by an LLM using
invisible code points: Unicode "tag" characters (U+E0000+ascii), bidirectional overrides
(Trojan Source), and zero-width characters. These almost never appear legitimately in AI
component surfaces, so detecting them is high-signal and low-false-positive — well suited to
an unattended CI gate.

Evidence renders invisible characters as ``<U+XXXX>`` and decodes any tag-character run back
to the ASCII it smuggles, so the hidden instruction is shown in the report.
"""

from __future__ import annotations

from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, Evidence, Finding, NeedsReview, Severity, ThreatClass
from skilltotal.scanners.base import MAX_EVIDENCE_PER_FINDING, RuleSpec, Scanner, ScanResult

CATEGORY = "hidden_unicode"

# Strong: essentially never legitimate in code / prompts / manifests.
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))  # overrides + isolates
_STRONG_ZERO_WIDTH = {0x200B, 0x2060}  # zero-width space, word joiner


def _is_tag(cp: int) -> bool:
    return 0xE0000 <= cp <= 0xE007F


def _is_strong(cp: int) -> bool:
    return _is_tag(cp) or cp in _BIDI or cp in _STRONG_ZERO_WIDTH


# Ambiguous: can appear legitimately (emoji ZWJ sequences, some scripts) -> needs_review.
_AMBIGUOUS = {0x200C, 0x200D, 0x00AD}


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
    return "".join(c if not _is_strong(ord(c)) and ord(c) not in _AMBIGUOUS
                   else f"<U+{ord(c):04X}>" for c in line)


class InvisibleUnicodeScanner(Scanner):
    name = "invisible_unicode"
    rules = [
        RuleSpec(
            id="ST-HIDDEN-UNICODE",
            category=CATEGORY,
            severity=Severity.HIGH,
            title="Hidden / invisible Unicode characters",
            description=(
                "Invisible Unicode was detected (tag characters / bidi overrides / "
                "zero-width). This is used to smuggle instructions past human review while "
                "remaining readable by an LLM."
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
            title="Ambiguous zero-width Unicode",
            description="Zero-width joiner/non-joiner detected (may be legitimate).",
            recommendation="Confirm the characters are part of legitimate text (emoji/script).",
            capability=None,
        ),
    ]

    def scan(self, index: FileIndex) -> ScanResult:
        evidence: list[Evidence] = []
        needs_review: list[NeedsReview] = []
        ambiguous_seen: set[str] = set()

        for f in index.files:
            for lineno, line in enumerate(f.text.splitlines(), start=1):
                strong = [c for c in line if _is_strong(ord(c))]
                if strong:
                    snippet = _render(line)[:200]
                    decoded = _decode_tags(line)
                    if decoded:
                        snippet += f"  [decoded hidden text: {decoded[:120]!r}]"
                    if len(evidence) < MAX_EVIDENCE_PER_FINDING:
                        evidence.append(
                            Evidence(file=f.relpath, line_start=lineno, line_end=lineno,
                                     snippet=snippet)
                        )
                elif any(ord(c) in _AMBIGUOUS for c in line) and f.relpath not in ambiguous_seen:
                    ambiguous_seen.add(f.relpath)
                    needs_review.append(
                        NeedsReview(
                            category=CATEGORY,
                            title="Ambiguous zero-width Unicode",
                            reason=(
                                f"Zero-width joiner/non-joiner at line {lineno} may be "
                                "legitimate (emoji/script) but can also hide text."
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
