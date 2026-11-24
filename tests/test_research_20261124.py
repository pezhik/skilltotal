"""Python decode-and-execute with the byte values held in a named list (research 2026-11-24)."""

from __future__ import annotations

from pathlib import Path

from skilltotal import engine
from skilltotal.collector import detect_component

BANNER = "# FIXTURE ONLY - synthetic detection test sample, not real malware\n"
CODES = "codes = [112, 114, 105, 110, 116, 40, 49, 41]\n"


def _ids(tmp_path: Path, body: str) -> set[str]:
    (tmp_path / "loader.py").write_text(BANNER + CODES + body, encoding="utf-8")
    report = engine.analyze_directory(tmp_path, detect_component(tmp_path, source=str(tmp_path)))
    return {f["id"] for f in report.to_dict()["findings"]}


def test_exec_of_bytes_from_named_list_is_decode_exec(tmp_path):
    assert "ST-OBF-DECODE-EXEC" in _ids(tmp_path, "exec(bytes(codes).decode())\n")


def test_bytearray_from_named_list_is_decode_exec(tmp_path):
    assert "ST-OBF-DECODE-EXEC" in _ids(tmp_path, "exec(bytearray(codes).decode())\n")


def test_printing_bytes_from_named_list_is_clean(tmp_path):
    assert "ST-OBF-DECODE-EXEC" not in _ids(tmp_path, "print(bytes(codes).decode())\n")


def test_short_named_list_is_not_reported(tmp_path):
    (tmp_path / "loader.py").write_text(
        BANNER + "codes = [112, 114, 105]\nexec(bytes(codes).decode())\n", encoding="utf-8"
    )
    report = engine.analyze_directory(tmp_path, detect_component(tmp_path, source=str(tmp_path)))
    assert "ST-OBF-DECODE-EXEC" not in {f["id"] for f in report.to_dict()["findings"]}
