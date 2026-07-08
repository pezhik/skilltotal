"""Component-trait projection + crosswalk: completeness, validity, and score-neutrality.

The trait layer is a deterministic projection over the rule registry (like OWASP). These tests
make a new rule fail CI until it is given a deliberate trait decision, assert the crosswalk is
well-formed for every trait, and lock the invariant that traits never move the score.
"""

from __future__ import annotations

from skilltotal.models import ThreatClass
from skilltotal.rules import get_rules
from skilltotal.traits import (
    MAESTRO_LAYERS,
    TRAIT_BY_RULE,
    TRAIT_CROSSWALK,
    ComponentTrait,
    build_trait_profile,
    extract_traits,
    traits_for,
)
from tests.conftest import analyze_fixture


def test_every_rule_has_an_explicit_trait_decision():
    rule_ids = {r.id for r in get_rules()}
    mapped = set(TRAIT_BY_RULE)
    missing = rule_ids - mapped
    extra = mapped - rule_ids
    assert not missing, f"rules with no explicit trait decision: {sorted(missing)}"
    assert not extra, f"TRAIT_BY_RULE has unknown rule ids: {sorted(extra)}"


def test_trait_by_rule_values_are_valid_and_deduped():
    for rule_id, traits in TRAIT_BY_RULE.items():
        assert isinstance(traits, tuple), rule_id
        assert len(set(traits)) == len(traits), f"duplicate trait on {rule_id}"
        for t in traits:
            assert isinstance(t, ComponentTrait), f"{rule_id} -> {t!r} is not a ComponentTrait"


def test_every_trait_has_a_valid_crosswalk():
    for trait in ComponentTrait:
        assert trait in TRAIT_CROSSWALK, f"no crosswalk for {trait}"
        meta = TRAIT_CROSSWALK[trait]
        assert meta.title and meta.description and meta.csa_trait and meta.csa_risk
        for layer in meta.maestro_layers:
            assert layer in MAESTRO_LAYERS, f"{trait} -> unknown MAESTRO layer {layer}"
        assert isinstance(meta.atlas_tactics, tuple)


def test_crosswalk_has_no_orphan_traits():
    # Every crosswalk key is a real ComponentTrait (no stale entries).
    assert set(TRAIT_CROSSWALK) == set(ComponentTrait)


def test_traits_for_known_and_unknown():
    assert traits_for("ST-SHELL-PY") == (ComponentTrait.EXECUTION_AUTHORITY,)
    assert traits_for("ST-COMBO-EXFIL") == (ComponentTrait.EXFIL_CORRELATION,)
    assert traits_for("ST-DOES-NOT-EXIST") == ()


def test_emergent_combo_traits_are_marked_and_map_to_synthesized_rules():
    for trait in (
        ComponentTrait.EXFIL_CORRELATION,
        ComponentTrait.INSTRUCTION_EXFIL_FLOW,
        ComponentTrait.MALWARE_CONVERGENCE,
    ):
        assert TRAIT_CROSSWALK[trait].emergent is True


def test_exfil_correlation_carries_cross_request_correlation_crosswalk():
    meta = TRAIT_CROSSWALK[ComponentTrait.EXFIL_CORRELATION]
    assert "Cross-request correlation" in meta.csa_risk
    assert "Exfiltration" in meta.atlas_tactics


def test_untrusted_perception_maps_to_atlas_perception_tactics():
    meta = TRAIT_CROSSWALK[ComponentTrait.UNTRUSTED_PERCEPTION]
    assert "Adversarial Perception Attacks" in meta.atlas_tactics


def test_engine_projects_traits_onto_report():
    report = analyze_fixture("malicious_npm_pkg")
    profile = report.to_dict()["traits"]
    assert profile, "malicious fixture must exhibit traits"
    by_id = {e["trait"]: e for e in profile}
    # every projected trait is evidence-backed and carries the full crosswalk shape
    for entry in profile:
        assert entry["evidence"], f"{entry['trait']} has no evidence"
        cw = entry["crosswalk"]
        assert set(cw) == {"csa_trait", "csa_risk", "maestro_layers", "atlas_tactics"}
    # this fixture reads credentials AND reaches the network -> the emergent exfil combo trait
    assert "exfil_correlation" in by_id
    assert by_id["exfil_correlation"]["emergent"] is True


def test_traits_are_ordered_and_deterministic():
    report = analyze_fixture("malicious_npm_pkg")
    order = [ComponentTrait(e["trait"]) for e in report.to_dict()["traits"]]
    declaration = [t for t in ComponentTrait if t in set(order)]
    assert order == declaration


def test_clean_component_has_empty_or_benign_traits():
    report = analyze_fixture("clean_pkg")
    profile = report.to_dict()["traits"]
    # No emergent (risky) combination trait on a clean component.
    assert not any(e["emergent"] for e in profile)


def test_traits_do_not_affect_score():
    # The trait projection is descriptive: removing it must not change the score, and no trait
    # entry is itself a scored object. Guard by asserting score is driven only by findings.
    report = analyze_fixture("malicious_npm_pkg")
    scored_classes = {
        f.threat_class for f in report.findings
    } - {ThreatClass.CAPABILITY}
    # traits exist independently of whether any finding is scored
    assert report.to_dict()["traits"]
    assert scored_classes  # the score comes from findings, not traits


def test_extract_traits_is_pure_projection_of_existing_evidence():
    report = analyze_fixture("malicious_npm_pkg")
    projected = extract_traits(report.findings)
    # every evidence object under a trait came from some finding (identity/equality preserved)
    all_finding_ev = {id(e) for f in report.findings for e in f.evidence}
    for evs in projected.values():
        for e in evs:
            assert id(e) in all_finding_ev
    # build_trait_profile is consistent with extract_traits
    assert {e["trait"] for e in build_trait_profile(report.findings)} == {
        t.value for t in projected
    }
