"""Scanner framework: rule specs, the Scanner contract, and shared helpers.

A :class:`RuleSpec` is the single source of truth for a detection rule — its identity,
severity, human text, the capability it implies, and (for the common case) the regex used
to match it. Simple scanners are therefore *data*: they declare rules and let
:func:`findings_from_rules` do the work. Complex scanners (MCP, install scripts,
obfuscation) still declare ``RuleSpec`` metadata (so ``rules list`` and the capability
engine see them) but implement custom :meth:`Scanner.scan` logic.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field

from skilltotal.file_index import FileIndex, IndexedFile
from skilltotal.models import Capability, Evidence, Finding, NeedsReview, Severity, ThreatClass
from skilltotal.text_normalize import normalize_with_map, original_span

# Cap evidence kept per finding so a noisy file cannot bloat the report.
MAX_EVIDENCE_PER_FINDING = 25


def deobfuscated_spans(
    index: FileIndex, pattern: re.Pattern[str]
) -> Iterator[tuple[IndexedFile, int, int]]:
    """Yield ``(file, start, end)`` for ``pattern`` matches found only after de-obfuscation.

    Folds away homoglyphs / full-width / diacritics / zero-width splicing (see
    :mod:`skilltotal.text_normalize`) and maps each match span back to the ORIGINAL file offsets
    so evidence stays anchored. Files whose normalized form equals the original are skipped — the
    ordinary raw-text scan already covered them — so this is nearly free for normal (ASCII) repos
    and only does work where text was actually obfuscated. The caller de-dupes against raw matches
    and builds evidence via ``file.evidence_for_span``.
    """
    for f in index.select():
        norm, idx = normalize_with_map(f.text)
        if not norm or norm == f.text:
            continue
        for m in pattern.finditer(norm):
            start, end = original_span(idx, m.start(), m.end())
            yield f, start, end


@dataclass(frozen=True)
class RuleSpec:
    """Metadata + (optional) detection pattern for a single rule."""

    id: str
    category: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    capability: Capability | None = None
    pattern: re.Pattern[str] | None = None
    suffixes: tuple[str, ...] | None = None
    names: tuple[str, ...] | None = None
    threat_class: ThreatClass = ThreatClass.CAPABILITY
    # How much Python code-context awareness this rule needs. A behavior/text detector matches
    # its own pattern literals when scanning analyzer/security source, so a match inside a
    # Python string/comment is demoted to NeedsReview (never scored). One of:
    #   "any"                  - count every match (default; e.g. AST/JSON-anchored rules).
    #   "comments"             - demote matches inside Python comments only (real positives are
    #                            value-strings, e.g. ST-EXPOSE-* `host="0.0.0.0"`).
    #   "strings_and_comments" - demote matches inside Python string literals OR comments (real
    #                            positives are never a plain .py value-string). C-family string
    #                            literals are NOT demoted (a credential path in a JS string is
    #                            real access); only C-family comments are.
    #   "strings_and_comments_all" - as above, PLUS demote matches inside C-family (.go/.js/.ts/.rs/
    #                            …) string literals. Used by ST-PROMPT-INJECTION: an injection
    #                            phrase held in a value-string (e.g. a security tool's own pattern
    #                            definition ``Description: "ignore previous instructions"``) is data
    #                            describing an attack, not a live directive.
    code_context: str = "any"

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "capability": self.capability.value if self.capability else "",
            "threat_class": self.threat_class.value,
        }


@dataclass
class ScanResult:
    """What every scanner returns."""

    findings: list[Finding] = field(default_factory=list)
    needs_review: list[NeedsReview] = field(default_factory=list)


class Scanner(ABC):
    """Base contract for all scanners."""

    name: str = ""
    rules: list[RuleSpec] = []

    @abstractmethod
    def scan(self, index: FileIndex) -> ScanResult:  # pragma: no cover - interface
        ...


class PatternScanner(Scanner):
    """A scanner whose behavior is fully described by its regex ``rules``."""

    def scan(self, index: FileIndex) -> ScanResult:
        return ScanResult(findings=findings_from_rules(index, self.rules))


def alternation(*patterns: str, flags: int = 0) -> re.Pattern[str]:
    """Compile several sub-patterns into one alternation regex."""
    return re.compile("|".join(f"(?:{p})" for p in patterns), flags)


def findings_from_rules(index: FileIndex, rules: list[RuleSpec]) -> list[Finding]:
    """Run every regex-bearing rule and produce at most one Finding per rule.

    All matches of a rule across the component are clustered into a single Finding whose
    ``evidence`` list holds the (de-duplicated, capped) match locations.
    """
    findings: list[Finding] = []
    for rule in rules:
        if rule.pattern is None:
            continue
        evidence = _collect_evidence(index, rule)
        if evidence:
            findings.append(_finding_from_rule(rule, evidence))
    return findings


def _collect_evidence(index: FileIndex, rule: RuleSpec) -> list[Evidence]:
    seen: set[tuple[str, int, int]] = set()
    evidence: list[Evidence] = []
    for _f, _m, ev in index.search(
        rule.pattern,  # type: ignore[arg-type]
        suffixes=rule.suffixes,
        names=rule.names,
    ):
        key = (ev.file, ev.line_start, ev.line_end)
        if key in seen:
            continue
        seen.add(key)
        evidence.append(ev)
        if len(evidence) >= MAX_EVIDENCE_PER_FINDING:
            break
    return evidence


def _finding_from_rule(rule: RuleSpec, evidence: list[Evidence]) -> Finding:
    description = rule.description
    if len(evidence) > 1:
        description = f"{description} ({len(evidence)} occurrence(s) shown as evidence)."
    return Finding(
        id=rule.id,
        severity=rule.severity,
        category=rule.category,
        title=rule.title,
        description=description,
        evidence=evidence,
        recommendation=rule.recommendation,
        threat_class=rule.threat_class,
    )
