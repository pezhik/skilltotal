"""Diff two SkillTotal reports — what changed between two versions of a component.

The unit of comparison is the serialized report (``Report.to_dict()`` shape), so both
freshly-scanned components and previously saved ``--json`` reports can be diffed. Findings
are matched by rule id; within a rule, individual evidence occurrences are matched by the
same line-independent fingerprint the baseline uses (``rule id + file + normalized
snippet``), so a pure line shift is not reported as a change.

Like the rest of the engine this module is a pure library: no printing, no filesystem
access, no process exit. Rendering lives in :mod:`skilltotal.report`; source resolution and
gating live in :mod:`skilltotal.cli`.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from skilltotal.baseline import evidence_fingerprint
from skilltotal.models import UNANALYZED_TITLES, Severity

_SEVERITY_ORDER = ("critical", "high", "medium", "low")


@dataclass
class DiffReport:
    """The normalized delta between an *old* and a *new* report."""

    old: dict[str, Any]
    new: dict[str, Any]
    risk_score_delta: int
    verdict_changed: bool
    # Rules present only in the new report (full finding dicts).
    new_findings: list[dict[str, Any]] = field(default_factory=list)
    # Rules present only in the old report (full finding dicts, as they were).
    resolved_findings: list[dict[str, Any]] = field(default_factory=list)
    # Rules present in both whose evidence set changed: id/severity/title plus the
    # added/removed evidence occurrences.
    changed_findings: list[dict[str, Any]] = field(default_factory=list)
    capabilities_added: list[str] = field(default_factory=list)
    capabilities_removed: list[str] = field(default_factory=list)
    # True when the two reports were produced by different rulesets: finding churn may then
    # come from detection changes rather than component changes.
    ruleset_mismatch: bool = False
    # Notes of the new report that say part of it was not analyzed (models.UNANALYZED_TITLES)
    # and that the old report did not have. A finding that disappears along with one of these
    # may have left the scan's view, not the component.
    coverage_gaps_added: list[dict[str, Any]] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "old": self.old,
            "new": self.new,
            "risk_score_delta": self.risk_score_delta,
            "verdict_changed": self.verdict_changed,
            "new_findings": self.new_findings,
            "resolved_findings": self.resolved_findings,
            "changed_findings": self.changed_findings,
            "capabilities_added": self.capabilities_added,
            "capabilities_removed": self.capabilities_removed,
            "ruleset_mismatch": self.ruleset_mismatch,
            "coverage_gaps_added": self.coverage_gaps_added,
            "summary": self.summary,
        }


def diff_reports(old: dict[str, Any], new: dict[str, Any]) -> DiffReport:
    """Compare two serialized reports (``Report.to_dict()`` shape) and return the delta."""
    old_findings = {f["id"]: f for f in old.get("findings", [])}
    new_findings = {f["id"]: f for f in new.get("findings", [])}

    added_rules = [new_findings[i] for i in new_findings if i not in old_findings]
    resolved_rules = [old_findings[i] for i in old_findings if i not in new_findings]

    changed: list[dict[str, Any]] = []
    for rule_id in old_findings.keys() & new_findings.keys():
        delta = _evidence_delta(rule_id, old_findings[rule_id], new_findings[rule_id])
        if delta is not None:
            changed.append(delta)

    old_caps = set(old.get("capabilities", {}))
    new_caps = set(new.get("capabilities", {}))

    old_score = int(old.get("risk_score", 0))
    new_score = int(new.get("risk_score", 0))
    old_verdict = (old.get("verdict") or {}).get("level")
    new_verdict = (new.get("verdict") or {}).get("level")

    diff = DiffReport(
        old=_side_summary(old),
        new=_side_summary(new),
        risk_score_delta=new_score - old_score,
        verdict_changed=old_verdict != new_verdict,
        new_findings=_sort_findings(added_rules),
        resolved_findings=_sort_findings(resolved_rules),
        changed_findings=sorted(changed, key=lambda c: c["id"]),
        capabilities_added=sorted(new_caps - old_caps),
        capabilities_removed=sorted(old_caps - new_caps),
        ruleset_mismatch=(
            old.get("metadata", {}).get("ruleset_version")
            != new.get("metadata", {}).get("ruleset_version")
        ),
        coverage_gaps_added=_coverage_gaps_added(old, new),
    )
    diff.summary = _summary(diff, old, new)
    return diff


def max_new_severity(diff: DiffReport) -> Severity | None:
    """Most severe risk *introduced* by the new version, or None if nothing was added.

    Counts both entirely new rules and new evidence occurrences on rules that already
    existed — either way the new version added that risk.
    """
    severities = [f["severity"] for f in diff.new_findings]
    severities += [c["severity"] for c in diff.changed_findings if c["added_evidence"]]
    if not severities:
        return None
    return max((Severity(s) for s in severities), key=lambda s: s.rank)


def _evidence_delta(
    rule_id: str, old_f: dict[str, Any], new_f: dict[str, Any]
) -> dict[str, Any] | None:
    """Evidence-level delta for a rule present in both reports, or None if unchanged.

    Occurrences are counted per fingerprint: a second copy of a line the old version already had
    (the same snippet in the same file) is an added occurrence, not the old one again."""
    added = _beyond(rule_id, new_f.get("evidence", []), old_f.get("evidence", []))
    removed = _beyond(rule_id, old_f.get("evidence", []), new_f.get("evidence", []))
    if not added and not removed:
        return None
    return {
        "id": rule_id,
        "severity": new_f.get("severity", old_f.get("severity")),
        "title": new_f.get("title", old_f.get("title", "")),
        "threat_class": new_f.get("threat_class", old_f.get("threat_class")),
        "added_evidence": added,
        "removed_evidence": removed,
    }


def _beyond(
    rule_id: str, side: list[dict[str, Any]], other: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """The occurrences in ``side`` beyond as many as ``other`` has of each, in fingerprint order."""
    left = Counter(_fp(rule_id, e) for e in other)
    extra: list[tuple[str, int, dict[str, Any]]] = []
    for k, e in enumerate(side):
        fp = _fp(rule_id, e)
        if left[fp] > 0:
            left[fp] -= 1
        else:
            extra.append((fp, k, e))
    return [e for _fp_key, _k, e in sorted(extra, key=lambda item: item[:2])]


def _fp(rule_id: str, evidence: dict[str, Any]) -> str:
    return evidence_fingerprint(rule_id, evidence.get("file", ""), evidence.get("snippet", ""))


def _coverage_gaps_added(old: dict[str, Any], new: dict[str, Any]) -> list[dict[str, Any]]:
    """The new report's not-analyzed notes that the old report has no copy of (the same title,
    file and reason)."""

    def gaps(report: dict[str, Any]) -> list[dict[str, Any]]:
        return [n for n in report.get("needs_review") or []
                if isinstance(n, dict) and n.get("title") in UNANALYZED_TITLES]

    seen = {(n.get("title"), n.get("file"), n.get("reason")) for n in gaps(old)}
    return [n for n in gaps(new) if (n.get("title"), n.get("file"), n.get("reason")) not in seen]


def _side_summary(report: dict[str, Any]) -> dict[str, Any]:
    component = report.get("component", {})
    metadata = report.get("metadata", {})
    return {
        "component": {
            "name": component.get("name", ""),
            "version": component.get("version", ""),
            "type": component.get("type", ""),
            "source": component.get("source", ""),
        },
        "risk_score": int(report.get("risk_score", 0)),
        "risk_level": report.get("risk_level", ""),
        "verdict_level": (report.get("verdict") or {}).get("level"),
        "engine_version": metadata.get("skilltotal_version"),
        "ruleset_version": metadata.get("ruleset_version"),
    }


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def key(f: dict[str, Any]) -> tuple[int, str]:
        sev = f.get("severity", "low")
        rank = _SEVERITY_ORDER.index(sev) if sev in _SEVERITY_ORDER else len(_SEVERITY_ORDER)
        return (rank, f.get("id", ""))

    return sorted(findings, key=key)


def _summary(diff: DiffReport, old: dict[str, Any], new: dict[str, Any]) -> str:
    sign = "+" if diff.risk_score_delta >= 0 else ""
    parts = [
        f"Risk {old.get('risk_score', 0)} -> {new.get('risk_score', 0)} "
        f"({sign}{diff.risk_score_delta}, {old.get('risk_level', '?')} -> "
        f"{new.get('risk_level', '?')})"
    ]
    parts.append(f"{len(diff.new_findings)} new finding(s)")
    parts.append(f"{len(diff.resolved_findings)} resolved")
    parts.append(f"{len(diff.changed_findings)} changed")
    if diff.coverage_gaps_added:
        parts.append(f"{len(diff.coverage_gaps_added)} new coverage gap(s)")
    return ": ".join([parts[0], ", ".join(parts[1:])])
