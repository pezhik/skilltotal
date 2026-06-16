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
TRIFECTA_FINDING_ID = "ST-FLOW-TRIFECTA"
CONVERGENCE_FINDING_ID = "ST-CONVERGENCE"
# Findings that represent access to sensitive data (credential locations / embedded secrets).
# Plain filesystem access is deliberately NOT here — reading ordinary files is a capability,
# not a risk, so a normal "reads files + uses network" tool is not flagged as exfiltration.
_SENSITIVE_DATA_IDS = frozenset({"ST-SENS-PATH", "ST-SENS-PATH-PY", "ST-SECRET-EMBEDDED"})
# A confirmed untrusted-instruction surface (the "untrusted content" axis of the trifecta).
_UNTRUSTED_CONTENT_IDS = frozenset({"ST-PROMPT-INJECTION"})


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


def trifecta_finding(
    findings: list[Finding],
    capabilities: dict[Capability, list[Evidence]],
    *,
    combo_fired: bool,
) -> Finding | None:
    """Synthesize the "lethal trifecta" exfiltration flow for an AI component.

    Fires when ALL THREE coincide: an untrusted-instruction surface (a confirmed
    prompt-injection finding), the ability to read files, and network egress — i.e. the
    component is exposed to instructions an attacker controls AND has the file-access + egress
    means to act on them. This is the combination that turns an injected instruction into data
    exfiltration.

    Gated to stay false-positive-free and low-noise: it requires an *actual* prompt-injection
    finding (not mere capability), and it is suppressed when the credential-specific
    ``ST-COMBO-EXFIL`` already fired (that stronger finding covers the same exfil concern).
    """
    if combo_fired:
        return None
    injection = [e for f in findings if f.id in _UNTRUSTED_CONTENT_IDS for e in f.evidence]
    fs_read = capabilities.get(Capability.FILESYSTEM_READ, [])
    net = capabilities.get(Capability.NETWORK_EGRESS, [])
    if not injection or not fs_read or not net:
        return None

    evidence = _dedupe(injection)[:2] + _dedupe(fs_read)[:2] + _dedupe(net)[:2]
    return Finding(
        id=TRIFECTA_FINDING_ID,
        severity=Severity.HIGH,
        category="exfiltration_path",
        title="Untrusted-instruction surface with file access and network egress",
        description=(
            "The component is exposed to untrusted instructions (a prompt-injection surface) and "
            "also can read files and send data over the network. Together these are the 'lethal "
            "trifecta' an attacker needs to turn an injected instruction into data exfiltration."
        ),
        evidence=evidence,
        recommendation=(
            "Remove the injectable instruction surface, or constrain the component so untrusted "
            "input cannot drive file reads and outbound network requests."
        ),
        threat_class=ThreatClass.RISKY_CONSTRUCT,
    )


def convergence_finding(findings: list[Finding]) -> Finding | None:
    """Synthesize an elevation finding when multiple distinct malicious indicators co-occur.

    Real malicious components stack deception and payload (e.g. an obfuscated dropper *and* a
    prompt injection); the convergence of two or more distinct malicious-indicator rules in one
    component sharply raises confidence that it is malicious. False-positive-free by construction:
    a benign component has zero malicious indicators, so this can never fire on one.

    Must run after ``_assign_threat_classes`` so each finding's ``threat_class`` is final.
    """
    malicious = [f for f in findings if f.threat_class is ThreatClass.MALICIOUS_INDICATOR]
    distinct_ids = {f.id for f in malicious}
    if len(distinct_ids) < 2:
        return None
    evidence = _dedupe([f.evidence[0] for f in malicious if f.evidence])[:6]
    titles = sorted({f.title for f in malicious})
    return Finding(
        id=CONVERGENCE_FINDING_ID,
        severity=Severity.HIGH,
        category="malware_convergence",
        title="Multiple malicious indicators in one component",
        description=(
            f"{len(distinct_ids)} distinct malicious indicators co-occur in this component "
            f"({', '.join(titles[:4])}). Real malware stacks deception with a payload, so their "
            "convergence sharply raises confidence the component is malicious."
        ),
        evidence=evidence,
        recommendation=(
            "Treat the component as malicious: do not install it, and review each indicator above."
        ),
        threat_class=ThreatClass.RISKY_CONSTRUCT,
    )
