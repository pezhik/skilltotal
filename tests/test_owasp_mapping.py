"""OWASP Agentic Skills Top 10 mapping: completeness + validity guards.

The mapping is a deterministic projection over the rule registry. These tests make a new rule
fail CI until it is given a deliberate taxonomy decision (a category or an explicit empty tuple),
so the standard mapping can never silently drift out of sync with the ruleset.
"""

from skilltotal.owasp import (
    OWASP_BY_RULE,
    OWASP_TAXONOMY,
    VALID_OWASP_IDS,
    owasp_for,
)
from skilltotal.rules import get_rules
from tests.conftest import analyze_fixture


def test_taxonomy_is_the_ast_top_10():
    ids = [c.id for c in OWASP_TAXONOMY]
    assert ids == [f"AST{n:02d}" for n in range(1, 11)]
    assert len(VALID_OWASP_IDS) == 10
    assert all(c.url.startswith("https://owasp.org/") for c in OWASP_TAXONOMY)


def test_every_rule_has_an_explicit_mapping():
    rule_ids = {r.id for r in get_rules()}
    mapped_ids = set(OWASP_BY_RULE)
    missing = rule_ids - mapped_ids
    extra = mapped_ids - rule_ids
    assert not missing, f"rules with no explicit OWASP decision: {sorted(missing)}"
    assert not extra, f"OWASP_BY_RULE has unknown rule ids: {sorted(extra)}"


def test_mapped_categories_are_valid_ast_ids():
    for rule_id, cats in OWASP_BY_RULE.items():
        assert isinstance(cats, tuple), rule_id
        assert len(set(cats)) == len(cats), f"duplicate category on {rule_id}"
        for c in cats:
            assert c in VALID_OWASP_IDS, f"{rule_id} -> unknown category {c}"


def test_owasp_for_known_and_unknown():
    assert owasp_for("ST-PROMPT-INJECTION") == ("AST04",)
    assert owasp_for("ST-INSTALL-DROPPER") == ("AST02",)
    assert owasp_for("ST-FS-PY-READ") == ()  # capability: no honest AST fit
    assert owasp_for("ST-DOES-NOT-EXIST") == ()


def test_engine_projects_owasp_onto_findings():
    report = analyze_fixture("malicious_npm_pkg")
    assert report.findings, "malicious fixture must produce findings"
    # every finding's owasp matches the central mapping and serializes as a list
    for f in report.findings:
        assert f.owasp == owasp_for(f.id)
        assert f.to_dict()["owasp"] == list(f.owasp)
    # a malicious package surfaces at least one mapped category, and capabilities stay empty
    cats = {c for f in report.findings for c in f.owasp}
    assert "AST02" in cats  # install-time supply-chain on this fixture
    assert any(f.owasp == () for f in report.findings)  # raw capabilities are not forced


def test_prompt_injection_maps_to_insecure_metadata():
    report = analyze_fixture("prompt_injection")
    pi = next((f for f in report.findings if f.id == "ST-PROMPT-INJECTION"), None)
    assert pi is not None and pi.owasp == ("AST04",)
