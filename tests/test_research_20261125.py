"""Research 2026-11-25: exec of text assembled from literal string fragments."""

from __future__ import annotations

from pathlib import Path

from skilltotal.engine import analyze_directory
from skilltotal.models import Component

BANNER = "# FIXTURE ONLY - synthetic detection test sample, not real malware\n"


def _ids(root: Path) -> set[str]:
    report = analyze_directory(root, Component(name="x", type="directory", source=str(root)))
    return {f.id for f in report.findings}


def _py(tmp_path: Path, body: str) -> Path:
    (tmp_path / "run.py").write_text(BANNER + body, encoding="utf-8")
    return tmp_path


def test_exec_of_joined_fragments_is_flagged(tmp_path: Path):
    body = 'parts = ["pri", "nt(", "1)"]\nexec("".join(parts))\n'
    assert "ST-OBF-DECODE-EXEC" in _ids(_py(tmp_path, body))


def test_exec_of_concatenated_fragments_is_flagged(tmp_path: Path):
    body = 'exec("pri" + "nt(" + "1)")\n'
    assert "ST-OBF-DECODE-EXEC" in _ids(_py(tmp_path, body))


def test_eval_of_joined_fragments_is_flagged(tmp_path: Path):
    body = 'x = eval("".join(("__imp", "ort__", "(1)")))\n'
    assert "ST-OBF-DECODE-EXEC" in _ids(_py(tmp_path, body))


def test_exec_with_runtime_part_stays_clean(tmp_path: Path):
    body = 'import sys\nexec("".join(["print(", repr(sys.argv[1]), ")"]))\n'
    assert "ST-OBF-DECODE-EXEC" not in _ids(_py(tmp_path, body))


def test_two_fragments_stay_clean(tmp_path: Path):
    body = 'exec("print(" + "1)")\n'
    assert "ST-OBF-DECODE-EXEC" not in _ids(_py(tmp_path, body))


def test_plain_join_not_reaching_exec_stays_clean(tmp_path: Path):
    body = 'line = " ".join(["a", "b", "c"])\nprint(line)\n'
    assert "ST-OBF-DECODE-EXEC" not in _ids(_py(tmp_path, body))
