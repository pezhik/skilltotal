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
from dataclasses import dataclass, field

from skilltotal.file_index import FileIndex
from skilltotal.models import Capability, Evidence, Finding, NeedsReview, Severity, ThreatClass

# Cap evidence kept per finding so a noisy file cannot bloat the report.
MAX_EVIDENCE_PER_FINDING = 25


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
    )
