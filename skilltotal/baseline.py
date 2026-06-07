"""Baseline suppression of known findings.

A baseline records stable *fingerprints* of accepted findings so they no longer appear in
future scans (useful for adopting SkillTotal on an existing repo, or for CI gates). A
fingerprint hashes ``(rule_id, file, normalized snippet)`` — deliberately **not** the line
number — so it survives edits that shift lines.

Suppression is applied at the evidence level before scoring: matched evidence is removed,
and a finding with no remaining evidence is dropped entirely (preserving the
"no finding without evidence" invariant) and does not contribute to the score.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from skilltotal.models import Evidence, Finding


def fingerprint(rule_id: str, evidence: Evidence) -> str:
    """Stable, line-independent identifier for one evidence occurrence."""
    payload = f"{rule_id}|{evidence.file}|{evidence.snippet.strip()}"
    # Not a security hash: just a stable fingerprint for baseline dedup/suppression.
    digest = hashlib.sha1(payload.encode("utf-8"), usedforsecurity=False)
    return digest.hexdigest()[:16]


def finding_fingerprints(finding: Finding) -> list[str]:
    return [fingerprint(finding.id, e) for e in finding.evidence]


def apply_suppressions(
    findings: list[Finding], suppressed: set[str]
) -> tuple[list[Finding], int]:
    """Drop suppressed evidence (and emptied findings). Returns (kept, suppressed_count)."""
    if not suppressed:
        return findings, 0
    kept: list[Finding] = []
    removed = 0
    for finding in findings:
        remaining = [e for e in finding.evidence if fingerprint(finding.id, e) not in suppressed]
        removed += len(finding.evidence) - len(remaining)
        if remaining:
            kept.append(
                Finding(
                    id=finding.id,
                    severity=finding.severity,
                    category=finding.category,
                    title=finding.title,
                    description=finding.description,
                    evidence=remaining,
                    recommendation=finding.recommendation,
                )
            )
    return kept, removed


def load_baseline(path: str | Path) -> set[str]:
    """Load a baseline file into a set of fingerprints.

    Accepts either a JSON object ``{"suppressed": [...]}`` or a plain JSON list.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        items = data.get("suppressed", [])
    elif isinstance(data, list):
        items = data
    else:
        items = []
    return {str(x) for x in items}


def build_baseline(findings: list[Finding]) -> dict[str, object]:
    """Build a baseline document covering every current finding occurrence."""
    fps = sorted({fp for f in findings for fp in finding_fingerprints(f)})
    return {
        "version": 1,
        "suppressed": fps,
    }
