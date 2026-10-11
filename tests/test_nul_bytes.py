"""A NUL byte does not hide code that its interpreter still runs.

Found by the pre-launch review: one NUL byte in the first 8 KB made the index treat a file as
binary and skip it. Node runs a `.js` file with a NUL inside a comment, and Python's `site` runs
the `import` lines of a `.pth` file whatever else the file holds, so a NUL bought a clean report
for code that runs.
"""

from __future__ import annotations

import json
from pathlib import Path

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.file_index import FileIndex
from skilltotal.guard import evaluate
from skilltotal.scanners.pth_exec import PthExecScanner

# Sanitized decode-and-execute: the payload decodes to `console.log(1)`.
_DROPPER = "eval(Buffer.from('Y29uc29sZS5sb2coMSk=','base64').toString());"


def test_a_pth_file_with_a_nul_byte_is_still_read(tmp_path: Path):
    (tmp_path / "evil.pth").write_bytes(
        b"\x00\nimport subprocess; subprocess.Popen(['sh','-c','id'])\n"
    )
    result = PthExecScanner().scan(FileIndex.build(tmp_path))
    finding = next(f for f in result.findings if f.id == "ST-PTH-EXEC")
    assert finding.evidence[0].line_start == 2  # the NUL does not shift the lines


def test_a_javascript_entry_point_with_a_nul_byte_is_still_read(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "some-pkg", "version": "1.0.0", "bin": {"some": "cli.js"}}),
        encoding="utf-8",
    )
    (tmp_path / "cli.js").write_bytes(b"// \x00\n" + _DROPPER.encode() + b"\n")
    report = analyze_directory(tmp_path, detect_component(tmp_path, source=str(tmp_path)))
    assert "ST-OBF-DECODE-EXEC" in {f.id for f in report.findings}
    assert not evaluate(report.to_dict()).allow


def test_files_that_are_not_run_as_code_are_still_binary(tmp_path: Path):
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00" + _DROPPER.encode())
    (tmp_path / "data.json").write_bytes(b'{"a": "\x00"}' + _DROPPER.encode())
    index = FileIndex.build(tmp_path)
    assert [f.relpath for f in index.files] == []
    assert index.stats["skipped_binary"] == 2
