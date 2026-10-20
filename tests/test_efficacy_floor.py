"""Tier-1 detection-efficacy gate (offline, deterministic).

Runs the static engine over the committed synthetic corpus in ``tests/eval_corpus/`` and enforces
three floors on every commit:

- **recall floor** — every positive (malicious) sample is flagged (malicious verdict OR risk
  high/critical), overall and per technique. Same uncompromising standard as the MUST_DETECT
  floor in ``test_offline_calibration.py``; a new positive is committed only once it detects.
- **precision floor** — zero false positives on negative (benign-but-tricky) samples: no
  malicious verdict, no high/critical risk, and no synthesized exfil finding.
- **coverage symmetry** — every technique under test carries BOTH a positive and a negative
  sample, so a detector is always exercised against its benign look-alike.
- **rule floor** — every per-rule sample under ``tests/eval_corpus/rules/`` meets its expectation
  (``fires/`` triggers the rule, ``silent/`` does not), and every rule behind an OWASP class count
  in ``docs/mcp-registry-survey.json`` has such samples.

This complements (does not replace) ``test_offline_calibration.py``: that file is a fast smoke
floor on hand-picked fixtures; this one quantifies recall/precision across a labeled corpus.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections import defaultdict
from pathlib import Path

from skilltotal.owasp import owasp_for
from skilltotal.rules import get_rules

_EFFICACY = Path(__file__).resolve().parent / "manual_eval" / "efficacy.py"
_spec = importlib.util.spec_from_file_location("efficacy", _EFFICACY)
efficacy = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules["efficacy"] = efficacy
_spec.loader.exec_module(efficacy)

_RESULTS, _METRICS = efficacy.run()


_REPORT = Path(__file__).resolve().parent.parent / "docs" / "efficacy-report.json"


def test_corpus_is_the_one_the_published_report_counts() -> None:
    # Guard against a missing, misplaced or partly skipped corpus making the floors vacuous: the
    # run must see exactly the samples the published report (and the README) counts. A sample
    # added or removed is a new report, regenerated with it.
    report = json.loads(_REPORT.read_text(encoding="utf-8"))
    regenerate = "regenerate: python tests/manual_eval/efficacy.py --out docs/efficacy-report"
    assert _METRICS.positives == report["positives"], (
        f"{_METRICS.positives} positive samples, the report counts {report['positives']}; "
        f"{regenerate}")
    assert _METRICS.negatives == report["negatives"], (
        f"{_METRICS.negatives} negative samples, the report counts {report['negatives']}; "
        f"{regenerate}")


def test_recall_floor() -> None:
    assert _METRICS.recall == 1.0, (
        "DETECTION REGRESSION: the engine missed known-malicious sample(s): "
        f"{_METRICS.false_negatives}. Every committed positive must be flagged "
        "(malicious verdict or high/critical risk)."
    )
    missed = {t: r for t, r in _METRICS.recall_by_technique.items() if r < 1.0}
    assert not missed, f"DETECTION REGRESSION: per-technique recall below 100%: {missed}"


def test_precision_floor() -> None:
    assert not _METRICS.false_positives, (
        "FALSE POSITIVE: benign-but-tricky sample(s) were flagged "
        f"(malicious / high-critical / synthesized exfil): {_METRICS.false_positives}."
    )


def test_coverage_symmetry() -> None:
    by_cell: dict[tuple[str, str], set[str]] = defaultdict(set)
    for s in efficacy.discover():
        by_cell[(s.owasp, s.technique)].add(s.polarity)
    missing = {
        f"{owasp}/{tech}": sorted({"positive", "negative"} - pols)
        for (owasp, tech), pols in by_cell.items()
        if pols != {"positive", "negative"}
    }
    assert not missing, f"each technique needs BOTH a positive and a negative; missing: {missing}"


# --- per-rule samples (tests/eval_corpus/rules/<RULE-ID>/{fires,silent}/<variant>/) ---------------

_RULE_SAMPLES = efficacy.discover_rule_samples()
_SURVEY = Path(__file__).resolve().parent.parent / "docs" / "mcp-registry-survey.json"


def test_every_sample_reports_exactly_its_expected_findings() -> None:
    # Recall and precision judge a sample by its verdict alone. A rule that stops firing on a
    # positive still flagged by another rule, or a new low finding on a benign look-alike, changes
    # neither. The committed rule ids per sample make every such change fail here, and a
    # deliberate one becomes a reviewed diff of expected_findings.json.
    expected = json.loads(efficacy.EXPECTED_FINDINGS.read_text(encoding="utf-8"))
    actual = efficacy.expected_findings(_RESULTS)
    changes = []
    for path in sorted(set(expected) | set(actual)):
        if path not in actual:
            changes.append(f"{path}: sample gone")
        elif path not in expected:
            changes.append(f"{path}: new sample, reports {actual[path]}")
        elif expected[path] != actual[path]:
            lost = sorted(set(expected[path]) - set(actual[path]))
            new = sorted(set(actual[path]) - set(expected[path]))
            changes.append(f"{path}: lost {lost}, new {new}")
    assert not changes, (
        "the findings on eval-corpus samples changed:\n  " + "\n  ".join(changes)
        + "\nIf the change is intended: python tests/manual_eval/efficacy.py --write-expected,"
        " then review the diff of tests/eval_corpus/expected_findings.json."
    )


def test_rule_samples_meet_their_expectation() -> None:
    assert _RULE_SAMPLES, "no per-rule samples found under tests/eval_corpus/rules/"
    assert not _METRICS.rule_misses, (
        "RULE REGRESSION: per-rule sample(s) did not meet their expectation (a fires/ sample "
        f"must trigger its rule, a silent/ look-alike must not): {_METRICS.rule_misses}"
    )


def test_rule_samples_name_real_rules_and_cover_both_sides() -> None:
    known = {r.id for r in get_rules()}
    sides: dict[str, set[str]] = defaultdict(set)
    for s in _RULE_SAMPLES:
        sides[s.rule_id].add(s.expect)
    unknown = sorted(set(sides) - known)
    assert not unknown, f"rule sample directories name unknown rule ids: {unknown}"
    one_sided = {r: sorted({"fires", "silent"} - e) for r, e in sides.items() if len(e) < 2}
    assert not one_sided, f"each rule needs BOTH fires/ and silent/ samples; missing: {one_sided}"


def test_every_rule_behind_a_survey_class_count_has_rule_samples() -> None:
    # The registry survey counts an OWASP class by rule presence, not by the malware verdict, and
    # most of the rules behind those counts are capability rules that never flag a sample.
    # Malicious recall cannot measure them, so each one must carry its own fires/silent samples.
    top_rules = json.loads(_SURVEY.read_text(encoding="utf-8"))["summary"]["top_rules"]
    behind_classes = {r for r in top_rules if owasp_for(r)}
    sampled = {s.rule_id for s in _RULE_SAMPLES}
    missing = sorted(behind_classes - sampled)
    assert not missing, f"rules behind the survey's OWASP class counts lack rule samples: {missing}"
