"""Risk scoring engine.

Score = sum of severity weights of all findings, capped at 100. The numeric score maps to
a :class:`~skilltotal.models.RiskLevel` band. A component that can both touch the
filesystem and reach the network gets a synthesized *critical* finding describing the
exfiltration path; this raises the score and surfaces the risk explicitly rather than
silently.
"""

from __future__ import annotations

from skilltotal.models import (
    Capability,
    Evidence,
    Finding,
    RiskLevel,
    Severity,
)

SCORE_CAP = 100

COMBO_FINDING_ID = "ST-COMBO-FS-NET"
_FS_CAPS = (Capability.FILESYSTEM_READ, Capability.FILESYSTEM_WRITE)


def _dedupe(evidence: list[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, int, int]] = set()
    out: list[Evidence] = []
    for e in evidence:
        key = (e.file, e.line_start, e.line_end)
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def compute_score(findings: list[Finding]) -> int:
    """Sum severity weights of all findings, capped at SCORE_CAP."""
    total = sum(f.severity.weight for f in findings)
    return min(total, SCORE_CAP)


def risk_level(score: int) -> RiskLevel:
    return RiskLevel.from_score(score)


def combined_fs_network_finding(
    capabilities: dict[Capability, list[Evidence]],
) -> Finding | None:
    """Return a synthesized critical finding if both filesystem and network are present.

    Its evidence is drawn from the contributing capabilities, so the invariant
    "no finding without evidence" still holds.
    """
    fs_evidence: list[Evidence] = []
    for cap in _FS_CAPS:
        fs_evidence.extend(capabilities.get(cap, []))
    net_evidence = capabilities.get(Capability.NETWORK_EGRESS, [])

    if not fs_evidence or not net_evidence:
        return None

    evidence = _dedupe(fs_evidence)[:3] + _dedupe(net_evidence)[:3]
    return Finding(
        id=COMBO_FINDING_ID,
        severity=Severity.CRITICAL,
        category="exfiltration_path",
        title="Combined filesystem access and network egress",
        description=(
            "The component can both access the filesystem and send data over the network. "
            "Together these form a potential data-exfiltration path."
        ),
        evidence=evidence,
        recommendation=(
            "Verify that data read from disk is never transmitted off-host without "
            "explicit, auditable user consent."
        ),
    )
