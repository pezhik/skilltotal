"""The eval corpus is data, never tests, whatever the pytest command line says (2026-11-22)."""

from __future__ import annotations

from pathlib import Path

TESTS = Path(__file__).resolve().parent


def test_conftest_keeps_the_corpus_and_the_benchmark_out_of_collection(request):
    # pytest loaded tests/conftest.py itself; read the list from the module it loaded.
    conftest = request.config.pluginmanager.get_plugin(str(TESTS / "conftest.py"))
    assert conftest is not None
    assert {"eval_corpus", "manual_eval"} <= set(conftest.collect_ignore)


def test_the_corpus_does_hold_files_shaped_as_tests():
    # Why the guard exists: without it these would run as tests.
    shaped = [p for p in (TESTS / "eval_corpus").rglob("test_*.py")]
    assert shaped, "no corpus sample is shaped as a test; the guard above may be dropped"
