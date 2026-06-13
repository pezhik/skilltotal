"""Risk scoring engine.

Score = sum of severity weights of the findings that represent *risk* — i.e. malicious
indicators and risky constructs — capped at 100. Neutral CAPABILITY findings (can read the
filesystem / reach the network / run a shell) are shown but do NOT add to the score:
capability is not risk, so a legitimate-but-powerful component is not pushed into the red by
what it can do. The numeric score maps to a :class:`~skilltotal.models.RiskLevel` band.

Sensitive-data access (a credential-location reference or an embedded secret) combined with
network egress synthesizes a critical risky-construct finding — the genuine credential-
exfiltration pattern. Plain filesystem + network is intentionally NOT flagged: reading ordinary
files and using the network is a neutral capability, so a legitimate-but-powerful tool is not
painted as an exfiltration path.
"""

from __future__ import annotations

from skilltotal.models import (
    Capability,
    Evidence,
    Finding,
    RiskLevel,
    Severity,
    ThreatClass,
)

SCORE_CAP = 100

# Only these threat classes contribute to the risk score; CAPABILITY is informational.
_SCORED_CLASSES = frozenset({ThreatClass.MALICIOUS_INDICATOR, ThreatClass.RISKY_CONSTRUCT})

COMBO_FINDING_ID = "ST-COMBO-EXFIL"
# Findings that represent access to sensitive data (credential locations / embedded secrets).
# Plain filesystem access is deliberately NOT here — reading ordinary files is a capability,
# not a risk, so a normal "reads files + uses network" tool is not flagged as exfiltration.
_SENSITIVE_DATA_IDS = frozenset({"ST-SENS-PATH", "ST-SENS-PATH-PY", "ST-SECRET-EMBEDDED"})


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
    """Sum severity weights of risk-bearing findings (malicious + risky), capped at SCORE_CAP.

    CAPABILITY findings are informational and contribute 0 — capability is not risk.
    """
    total = sum(f.severity.weight for f in findings if f.threat_class in _SCORED_CLASSES)
    return min(total, SCORE_CAP)


def risk_level(score: int) -> RiskLevel:
    return RiskLevel.from_score(score)


def exfiltration_finding(
    findings: list[Finding],
    capabilities: dict[Capability, list[Evidence]],
) -> Finding | None:
    """Synthesize a critical risky-construct finding for a credential-exfiltration path.

    Fires only when the component BOTH accesses sensitive data (a credential-location reference
    or an embedded secret — see ``_SENSITIVE_DATA_IDS``) AND can reach the network. This is the
    genuinely risky combination (read a secret, send it off-host); plain filesystem + network is
    a neutral capability and is intentionally not flagged here. Evidence is drawn from the
    contributing findings/capabilities so the "no finding without evidence" invariant holds.
    """
    sens_evidence: list[Evidence] = [
        e for f in findings if f.id in _SENSITIVE_DATA_IDS for e in f.evidence
    ]
    net_evidence = capabilities.get(Capability.NETWORK_EGRESS, [])

    if not sens_evidence or not net_evidence:
        return None

    evidence = _dedupe(sens_evidence)[:3] + _dedupe(net_evidence)[:3]
    return Finding(
        id=COMBO_FINDING_ID,
        severity=Severity.CRITICAL,
        category="exfiltration_path",
        title="Sensitive-data access combined with network egress",
        description=(
            "The component references credential/secret locations and can also send data over "
            "the network. Together these form a credential-exfiltration path."
        ),
        evidence=evidence,
        recommendation=(
            "Verify that secrets read from disk are never transmitted off-host without "
            "explicit, auditable user consent."
        ),
        threat_class=ThreatClass.RISKY_CONSTRUCT,
    )
