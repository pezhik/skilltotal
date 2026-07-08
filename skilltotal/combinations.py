"""Declarative registry of *combination* findings — emergent risk from co-occurring signals.

The most dangerous shapes in an AI component are rarely a single finding; they emerge when
independent behaviors co-occur (read a secret AND reach the network; an install hook AND a
decode-exec payload). SkillTotal synthesizes those as dedicated risky-construct findings
(``ST-COMBO-EXFIL`` / ``ST-FLOW-TRIFECTA`` / ``ST-INSTALL-DROPPER`` / ``ST-CONVERGENCE``).

This module is the single, ordered source of truth for *which* combinations exist and *when*
each is evaluated — the orchestration the engine used to hardcode as four sequential calls.
Each combination is declared as data (:class:`Combination`) with a short technique label (for
the public benchmark's per-technique view) and a ``synth`` adapter; the calibrated detection
logic itself still lives in :mod:`skilltotal.scoring` (unchanged — the recall gate and the
per-finding golden set guard it). Adding a new combination is therefore a registry entry plus
its evaluator, not an edit to the engine's control flow.

Evaluation happens in two phases, because one combination depends on the others' output:

* ``PRE_CLASSIFICATION`` — run over the base findings before threat classes are assigned;
  order matters (``ST-COMBO-EXFIL`` before ``ST-FLOW-TRIFECTA``, which is suppressed once the
  stronger credential combo has fired).
* ``POST_CLASSIFICATION`` — run after ``_assign_threat_classes`` so it can count the now-final
  ``malicious_indicator`` findings (``ST-CONVERGENCE``).

Each combination id has a matching :class:`~skilltotal.scanners.base.RuleSpec` in
:mod:`skilltotal.rules` and a :class:`~skilltotal.traits.ComponentTrait` in
:mod:`skilltotal.traits`; ``tests/test_combinations.py`` locks those in sync.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum

from skilltotal.models import Capability, Component, Evidence, Finding
from skilltotal.scoring import (
    COMBO_FINDING_ID,
    CONVERGENCE_FINDING_ID,
    INSTALL_DROPPER_FINDING_ID,
    TRIFECTA_FINDING_ID,
    convergence_finding,
    exfiltration_finding,
    install_dropper_finding,
    trifecta_finding,
)


class Phase(str, Enum):
    """When a combination is evaluated, relative to threat-class assignment."""

    PRE_CLASSIFICATION = "pre_classification"
    POST_CLASSIFICATION = "post_classification"


# Uniform evaluator signature so the engine can dispatch every combination the same way.
# ``fired`` is the set of combination ids that have already fired this run (for suppression).
Synth = Callable[
    [list[Finding], dict[Capability, list[Evidence]], "Component | None", "set[str]"],
    "Finding | None",
]


@dataclass(frozen=True)
class Combination:
    """One synthesized combination finding, declared as data + its evaluator adapter."""

    id: str
    technique: str  # short human label for the public per-technique benchmark
    phase: Phase
    synth: Synth


def _exfil(findings, capabilities, component, fired):
    return exfiltration_finding(findings, capabilities, component)


def _trifecta(findings, capabilities, component, fired):
    # Suppressed once the stronger credential-specific combo has fired (same exfil concern).
    return trifecta_finding(findings, capabilities, combo_fired=COMBO_FINDING_ID in fired)


def _dropper(findings, capabilities, component, fired):
    return install_dropper_finding(findings)


def _convergence(findings, capabilities, component, fired):
    return convergence_finding(findings)


# Ordered registry. PRE order is load-bearing: ST-COMBO-EXFIL must precede ST-FLOW-TRIFECTA so
# the trifecta's suppression sees the credential combo. ST-CONVERGENCE is POST because it counts
# the final malicious-indicator classes.
COMBINATIONS: tuple[Combination, ...] = (
    Combination(
        id=COMBO_FINDING_ID,
        technique="Credential exfiltration (sensitive-data read + network egress)",
        phase=Phase.PRE_CLASSIFICATION,
        synth=_exfil,
    ),
    Combination(
        id=TRIFECTA_FINDING_ID,
        technique="Lethal trifecta (untrusted-instruction surface + file read + egress)",
        phase=Phase.PRE_CLASSIFICATION,
        synth=_trifecta,
    ),
    Combination(
        id=INSTALL_DROPPER_FINDING_ID,
        technique="Install-time dropper (lifecycle hook + decode-exec/credential payload)",
        phase=Phase.PRE_CLASSIFICATION,
        synth=_dropper,
    ),
    Combination(
        id=CONVERGENCE_FINDING_ID,
        technique="Malicious-indicator convergence (>=2 distinct indicators)",
        phase=Phase.POST_CLASSIFICATION,
        synth=_convergence,
    ),
)


def _phase(phase: Phase) -> tuple[Combination, ...]:
    return tuple(c for c in COMBINATIONS if c.phase is phase)


def pre_classification() -> tuple[Combination, ...]:
    """Combinations evaluated over base findings, before threat classes are assigned."""
    return _phase(Phase.PRE_CLASSIFICATION)


def post_classification() -> tuple[Combination, ...]:
    """Combinations evaluated after threat classes are final (e.g. convergence)."""
    return _phase(Phase.POST_CLASSIFICATION)
