"""Schema 1.8: a code file the scan did not read makes the verdict say the analysis was partial.

A code file over the size cap (MAX_FILE_BYTES) or a minified bundle is not read, yet the headline
said "No significant risks found" and only `--fail-on-unanalyzed` caught it. Now a low verdict
says "Partially analyzed", and `verdict.unanalyzed_files` counts those files by reason. Scores do
not change: unread code is not evidence of risk. Data and assets (a large JSON file), test code,
and a minified copy shipped next to its readable source are not counted.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal.cli import EXIT_FAIL_ON_HIGH, main
from skilltotal.engine import analyze_directory
from skilltotal.file_index import MAX_FILE_BYTES
from skilltotal.models import Component

LARGE_JS = "// generated\n" + "const a = 1;\n" * (MAX_FILE_BYTES // 13 + 10)
# A bundle: large, with almost no line breaks.
MINIFIED = "var a=1;" * 4000 + "\n"
LARGE_JSON = '{"rows": [' + ",".join(['{"k": 1}'] * (MAX_FILE_BYTES // 8 + 10)) + "]}\n"


def _scan(root: Path, files: dict[str, str]):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    return analyze_directory(root, Component(name="x", type="local", source=str(root)))


def test_a_code_file_too_large_to_read_makes_the_verdict_partial(tmp_path):
    report = _scan(tmp_path, {"main.py": "x = 1\n", "lib/generated.js": LARGE_JS})
    assert report.verdict["headline"].startswith("Partially analyzed")
    assert "too large" in report.verdict["headline"]
    assert report.verdict["unanalyzed_files"] == {"too_large": 1}
    assert report.verdict["level"] == "low"
    assert report.risk_score == 0


def test_a_minified_bundle_makes_the_verdict_partial(tmp_path):
    report = _scan(tmp_path, {"main.py": "x = 1\n", "lib/bundle.js": MINIFIED})
    assert report.verdict["headline"].startswith("Partially analyzed")
    assert "minified" in report.verdict["headline"]
    assert report.verdict["unanalyzed_files"] == {"minified": 1}
    assert report.risk_score == 0


def test_languages_and_skipped_files_are_both_named(tmp_path):
    report = _scan(tmp_path, {
        "main.go": "package main\nfunc main() {}\n", "lib/bundle.js": MINIFIED,
    })
    headline = report.verdict["headline"]
    assert headline.startswith("Partially analyzed")
    assert "Go" in headline and "minified" in headline


def test_data_test_code_and_minified_copies_do_not_count(tmp_path):
    report = _scan(tmp_path, {
        "main.py": "x = 1\n",
        "data/rows.json": LARGE_JSON,
        "tests/fixtures/bundle.js": MINIFIED,
        "lib/widget.js": "export const widget = 1;\n",
        "lib/widget.min.js": MINIFIED,
    })
    assert "unanalyzed_files" not in report.verdict
    assert not report.verdict["headline"].startswith("Partially analyzed")


def test_a_higher_verdict_keeps_its_headline_and_still_counts_the_files(tmp_path):
    dropper = "import base64\nexec(base64.b64decode(b'cHJpbnQoMSk='))\n"
    report = _scan(tmp_path, {"main.py": dropper, "lib/bundle.js": MINIFIED})
    assert report.verdict["level"] == "malicious"
    assert report.verdict["headline"] == "Malicious indicators found"
    assert report.verdict["unanalyzed_files"] == {"minified": 1}


def test_fail_on_unanalyzed_counts_skipped_code(tmp_path, capsys):
    for name, files in {
        "large": {"main.py": "x = 1\n", "lib/generated.js": LARGE_JS},
        "minified": {"main.py": "x = 1\n", "lib/bundle.js": MINIFIED},
    }.items():
        root = tmp_path / name
        _scan(root, files)
        assert main(["scan", str(root), "--json", "--fail-on-unanalyzed"]) == EXIT_FAIL_ON_HIGH
    capsys.readouterr()
