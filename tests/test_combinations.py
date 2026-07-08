"""Combination registry: well-formed, in sync with rules + traits, correctly phased/ordered.

The registry is the single source of truth for which synthesized combination findings exist and
when each runs. These tests lock it against the rule registry and the trait taxonomy, and pin the
load-bearing ordering (the exfil combo must precede the trifecta it suppresses). Behavioral
equivalence with the previous hardcoded engine flow is covered by the full scanner/scoring suite.
"""

from __future__ import annotations

from skilltotal.combinations import (
    COMBINATIONS,
    COMBO_FINDING_ID,
    CONVERGENCE_FINDING_ID,
    Phase,
    post_classification,
    pre_classification,
)
from skilltotal.rules import get_rules
from skilltotal.scoring import TRIFECTA_FINDING_ID
from skilltotal.traits import traits_for
from tests.conftest import analyze_fixture


def test_registry_ids_are_unique_and_partition_by_phase():
    ids = [c.id for c in COMBINATIONS]
    assert len(ids) == len(set(ids)), "combination ids must be unique"
    assert set(pre_classification()) | set(post_classification()) == set(COMBINATIONS)
    assert not (set(pre_classification()) & set(post_classification()))


def test_every_combination_has_a_rule_and_a_trait():
    rule_ids = {r.id for r in get_rules()}
    for c in COMBINATIONS:
        assert c.id in rule_ids, f"combination {c.id} has no RuleSpec"
        assert traits_for(c.id), f"combination {c.id} has no ComponentTrait mapping"
        assert c.technique, f"combination {c.id} has no technique label"


def test_pre_order_puts_exfil_before_trifecta():
    # The trifecta is suppressed once the credential-specific exfil combo has fired, so the
    # exfil combo MUST be evaluated first.
    pre_ids = [c.id for c in pre_classification()]
    assert COMBO_FINDING_ID in pre_ids and TRIFECTA_FINDING_ID in pre_ids
    assert pre_ids.index(COMBO_FINDING_ID) < pre_ids.index(TRIFECTA_FINDING_ID)


def test_convergence_is_post_classification():
    # Convergence counts final malicious-indicator classes, so it runs after classification.
    assert [c.id for c in post_classification()] == [CONVERGENCE_FINDING_ID]
    assert all(c.phase is Phase.PRE_CLASSIFICATION for c in pre_classification())


def test_exfil_combo_still_fires_end_to_end():
    # Behavioral anchor: the credential-exfil combo still synthesizes through the registry path.
    report = analyze_fixture("malicious_npm_pkg")
    assert any(f.id == COMBO_FINDING_ID for f in report.findings)


def test_trifecta_suppressed_when_exfil_fired():
    # When the stronger exfil combo fires, the trifecta must not also fire (same run).
    report = analyze_fixture("malicious_npm_pkg")
    ids = {f.id for f in report.findings}
    if COMBO_FINDING_ID in ids:
        assert TRIFECTA_FINDING_ID not in ids
