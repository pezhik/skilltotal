"""SkillTotal's own outputs in a scanned folder are not scanned as component content.

After `skilltotal scan . --sarif --output skilltotal.sarif`, a later scan of the same folder read
the SARIF and reported MALICIOUS from the rule descriptions in it (they quote detection patterns).
A SARIF whose tool is SkillTotal, a JSON report with SkillTotal's report shape and metadata, and a
baseline written by `--write-baseline` are recognised by their content (pure JSON with that exact
shape), not by name, set aside, and listed in needs_review. Anything else, including a file that
looks like one but is not pure JSON or carries extra keys, is scanned as before.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal.baseline import build_baseline
from skilltotal.engine import analyze_directory
from skilltotal.models import UNANALYZED_TITLES, Component
from skilltotal.report import render_json
from skilltotal.sarif import render_sarif

OWN_OUTPUTS = "SkillTotal output files not analyzed"
DROPPER = (
    "import base64\n"
    "exec(base64.b64decode(PAYLOAD))\n"
    "open('/home/u/.ssh/id_rsa').read()\n"
)


def _report_of(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "drop.py").write_text("PAYLOAD = b'cHJpbnQoMSk='\n" + DROPPER, encoding="utf-8")
    report = analyze_directory(src, Component(name="src", type="local", source=str(src)))
    assert report.verdict["has_malicious_indicators"]  # the outputs below quote real findings
    return report


def _scan(root: Path):
    return analyze_directory(root, Component(name="c", type="local", source=str(root)))


@pytest.fixture
def outputs(tmp_path: Path) -> dict[str, str]:
    report = _report_of(tmp_path)
    return {
        "skilltotal.sarif": render_sarif(report),
        "reports/last-scan.json": render_json(report),
        ".skilltotal-baseline.json": json.dumps(build_baseline(report.findings), indent=2),
    }


def test_own_outputs_are_not_scanned_and_are_listed(tmp_path: Path, outputs):
    root = tmp_path / "component"
    for rel, text in outputs.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    (root / "main.py").write_text("print('hello')\n", encoding="utf-8")
    report = _scan(root)
    assert not report.findings
    assert report.risk_score == 0
    assert not report.verdict["has_malicious_indicators"]
    note = next(n for n in report.needs_review if n.title == OWN_OUTPUTS)
    for rel in outputs:
        assert rel in note.reason
    assert OWN_OUTPUTS not in UNANALYZED_TITLES  # a report is not a gap in the analysis


def test_the_name_alone_does_not_skip_a_file(tmp_path: Path):
    root = tmp_path / "component"
    root.mkdir()
    (root / "skilltotal.sarif.py").write_text(DROPPER, encoding="utf-8")
    report = _scan(root)
    assert report.verdict["has_malicious_indicators"]


def test_a_look_alike_with_code_or_extra_keys_is_scanned(tmp_path: Path, outputs):
    root = tmp_path / "component"
    root.mkdir()
    sarif = json.loads(outputs["skilltotal.sarif"])
    sarif["x-payload"] = "exec(base64.b64decode(PAYLOAD))"
    (root / "a.sarif").write_text(json.dumps(sarif), encoding="utf-8")
    other = json.loads(outputs["skilltotal.sarif"])
    other["runs"][0]["tool"]["driver"]["name"] = "OtherTool"
    (root / "b.sarif").write_text(json.dumps(other), encoding="utf-8")
    # Our report followed by script text: not pure JSON.
    (root / "c.js").write_text(outputs["reports/last-scan.json"] + "\n;eval(atob(x));\n",
                               encoding="utf-8")
    report = _scan(root)
    assert not any(n.title == OWN_OUTPUTS for n in report.needs_review)
    scanned = {e.file for f in report.findings for e in f.evidence} | {
        n.file for n in report.needs_review
    }
    assert {"a.sarif", "b.sarif", "c.js"} & scanned


def test_scanning_a_folder_after_writing_a_report_into_it(tmp_path: Path, capsys):
    from skilltotal.cli import main

    root = tmp_path / "component"
    root.mkdir()
    (root / "main.py").write_text("import os\nos.system('make')\n", encoding="utf-8")
    main(["scan", str(root), "--sarif", "--output", str(root / "skilltotal.sarif")])
    main(["scan", str(root), "--json", "--output", str(root / "report.json")])
    main(["scan", str(root), "--write-baseline", str(root / "baseline.json")])
    capsys.readouterr()
    main(["scan", str(root), "--json"])
    report = json.loads(capsys.readouterr().out)
    assert not report["verdict"]["has_malicious_indicators"]
    assert {e["file"] for f in report["findings"] for e in f["evidence"]} == {"main.py"}
    note = next(n for n in report["needs_review"] if n["title"] == OWN_OUTPUTS)
    for name in ("skilltotal.sarif", "report.json", "baseline.json"):
        assert name in note["reason"]


def test_a_baseline_with_something_else_in_it_is_scanned(tmp_path: Path):
    root = tmp_path / "component"
    root.mkdir()
    doc = {"version": 1, "suppressed": ["0123456789abcdef", "~/.ssh/id_rsa"]}
    (root / "baseline.json").write_text(json.dumps(doc), encoding="utf-8")
    report = _scan(root)
    assert not any(n.title == OWN_OUTPUTS for n in report.needs_review)
