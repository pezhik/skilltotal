"""Evidence-based capability extraction.

Capabilities are a pure projection over findings: each finding's rule declares the
:class:`~skilltotal.models.Capability` it implies, so we simply regroup the evidence the
findings already proved. No file is re-scanned, and every capability is therefore
evidence-backed by construction.
"""

from __future__ import annotations

from skilltotal.models import Capability, Evidence, Finding
from skilltotal.scanners import rule_by_id

# Evidence kept per capability (capabilities can aggregate many findings).
MAX_EVIDENCE_PER_CAPABILITY = 25


def extract_capabilities(findings: list[Finding]) -> dict[Capability, list[Evidence]]:
    rules = rule_by_id()
    caps: dict[Capability, list[Evidence]] = {}
    for finding in findings:
        rule = rules.get(finding.id)
        capability = rule.capability if rule else None
        if capability is None:
            continue
        bucket = caps.setdefault(capability, [])
        for ev in finding.evidence:
            if len(bucket) >= MAX_EVIDENCE_PER_CAPABILITY:
                break
            bucket.append(ev)
    return caps
