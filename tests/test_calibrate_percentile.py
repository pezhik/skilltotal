"""The calibration summary reports the median and p90 of needs_review, not only the mean."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_PATH = Path(__file__).resolve().parent / "manual_eval" / "calibrate.py"
_spec = importlib.util.spec_from_file_location("calibrate_under_test", _PATH)
calibrate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(calibrate)


def test_percentile_is_nearest_rank():
    values = [0, 0, 1, 2, 3, 5, 8, 13, 40, 398]
    assert calibrate._percentile(values, 50) == 3.0
    assert calibrate._percentile(values, 90) == 40.0
    assert calibrate._percentile([7], 90) == 7.0
    assert calibrate._percentile([], 50) == 0.0
