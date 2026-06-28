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

This complements (does not replace) ``test_offline_calibration.py``: that file is a fast smoke
floor on hand-picked fixtures; this one quantifies recall/precision across a labeled corpus.
"""

from __future__ import annotations

import importlib.util
import sys
from collections import defaultdict
from pathlib import Path

_EFFICACY = Path(__file__).resolve().parent / "manual_eval" / "efficacy.py"
_spec = importlib.util.spec_from_file_location("efficacy", _EFFICACY)
efficacy = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
sys.modules["efficacy"] = efficacy
_spec.loader.exec_module(efficacy)

_RESULTS, _METRICS = efficacy.run()


def test_corpus_is_non_trivial() -> None:
    # Guard against an empty/misplaced corpus silently making the floors vacuous.
    assert _METRICS.positives >= 15, f"too few positive samples: {_METRICS.positives}"
    assert _METRICS.negatives >= 10, f"too few negative samples: {_METRICS.negatives}"


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
