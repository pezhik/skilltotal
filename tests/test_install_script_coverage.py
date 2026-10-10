"""What npm runs at install time is always read, and a script that cannot be read is never "clean".

Found by a pre-launch audit: a dropper in a one-line `setup.js` of 84 KB, run by `postinstall`,
was set aside as a minified bundle, so the package scored 0/100 with "no malicious indicators".
"""

from __future__ import annotations

import json
from pathlib import Path

from skilltotal.agent_hook import hook_response
from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory
from skilltotal.file_index import MAX_FILE_BYTES, FileIndex
from skilltotal.guard import evaluate
from skilltotal.models import UNANALYZED_INSTALL_SCRIPT

# A sanitized decode-and-execute: the payload decodes to `console.log(1)`.
_DROPPER = "eval(Buffer.from('Y29uc29sZS5sb2coMSk=','base64').toString());"


def _package(root: Path, scripts: dict[str, str]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": "some-pkg", "version": "1.0.0", "scripts": scripts}),
        encoding="utf-8",
    )


def _analyze(root: Path):
    return analyze_directory(root, detect_component(root, source=str(root)))


def test_a_minified_install_script_is_analyzed(tmp_path):
    _package(tmp_path, {"postinstall": "node setup.js"})
    # One line of 30 KB: the shape the index sets aside as a bundle.
    (tmp_path / "setup.js").write_text("var a='" + "x" * 30_000 + "';" + _DROPPER,
                                       encoding="utf-8")
    report = _analyze(tmp_path)
    assert "ST-OBF-DECODE-EXEC" in {f.id for f in report.findings}
    assert report.verdict["has_malicious_indicators"]


def test_a_minified_file_npm_does_not_run_at_install_is_still_set_aside(tmp_path):
    _package(tmp_path, {"build": "node setup.js"})
    (tmp_path / "setup.js").write_text("var a='" + "x" * 30_000 + "';", encoding="utf-8")
    index = FileIndex.build(tmp_path)
    assert index.minified == ["setup.js"]


def test_an_install_script_too_large_to_read_blocks_the_guard(tmp_path):
    _package(tmp_path, {"preinstall": "node ./bin/install.js && echo done"})
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "install.js").write_text("//" + "x" * (MAX_FILE_BYTES + 10),
                                                 encoding="utf-8")
    report = _analyze(tmp_path)
    notes = [n for n in report.needs_review if n.title == UNANALYZED_INSTALL_SCRIPT]
    assert [n.file for n in notes] == ["bin/install.js"]
    assert "preinstall" in notes[0].reason and "MiB" in notes[0].reason

    decision = evaluate(report.to_dict())
    assert not decision.allow
    assert "install script not analyzed: `bin/install.js`" in decision.reasons


def test_words_of_a_script_that_are_not_files_inside_the_package_are_ignored(tmp_path):
    _package(tmp_path, {"install": "node-gyp rebuild || node ../../outside.js",
                        "postinstall": "husky install"})
    report = _analyze(tmp_path)
    assert not [n for n in report.needs_review if n.title == UNANALYZED_INSTALL_SCRIPT]


def test_the_hook_asks_about_an_install_script_it_could_not_read():
    report = {
        "risk_level": "low", "risk_score": 0,
        "verdict": {"has_malicious_indicators": False, "headline": "No malicious indicators"},
        "needs_review": [{"category": "coverage", "title": UNANALYZED_INSTALL_SCRIPT,
                          "file": "bin/install.js"}],
    }
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
             "tool_input": {"command": "npm install some-pkg"}}
    out = hook_response(event, scan=lambda s, t: report)
    spec = out["hookSpecificOutput"]
    assert spec["permissionDecision"] == "ask"
    assert ("npm:some-pkg: the install script `bin/install.js` could not be analyzed, so nothing "
            "in it was checked.") in spec["permissionDecisionReason"]


def test_a_cached_verdict_keeps_the_unread_install_script(tmp_path, monkeypatch):
    from skilltotal import cli, collector

    monkeypatch.setenv("SKILLTOTAL_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(collector, "resolve_release", lambda source, timeout=0: None)
    full = {
        "risk_level": "low", "risk_score": 0,
        "verdict": {"has_malicious_indicators": False, "headline": "No malicious indicators"},
        "findings": [],
        "needs_review": [
            {"category": "coverage", "title": UNANALYZED_INSTALL_SCRIPT, "file": "x.js",
             "reason": "...", "line": None},
            {"category": "coverage", "title": "Minified bundle not analyzed", "file": None,
             "reason": "...", "line": None},
        ],
    }
    monkeypatch.setattr(cli, "_hook_scan", lambda source, timeout: full)
    cli._hook_scan_cached("npm:some-pkg", 20)
    cached = cli._hook_scan_cached("npm:some-pkg", 20)
    assert [n["title"] for n in cached["needs_review"]] == [UNANALYZED_INSTALL_SCRIPT]
    assert not evaluate(cached).allow


def test_only_a_source_map_with_no_code_in_it_is_skipped(tmp_path):
    # TypeScript writes maps with positions and names only: nothing to analyze, and an SDK ships
    # one per module. A map that carries source text can hide code the package loads itself.
    codeless = {"version": 3, "file": "index.js", "sources": ["../src/index.ts"],
                "names": ["Client", "_request"], "mappings": "AAAA;AACA"}
    (tmp_path / "index.js.map").write_text(json.dumps(codeless), encoding="utf-8")
    with_code = {**codeless, "sourcesContent": ["export default 1;\n"]}
    (tmp_path / "bundle.min.js.map").write_text(json.dumps(with_code), encoding="utf-8")
    hiding = {**codeless, "names": ["require('child_process').execSync('id')"]}
    (tmp_path / "names.js.map").write_text(json.dumps(hiding), encoding="utf-8")
    # A `.map` that is not a source map is an ordinary file.
    (tmp_path / "payload.map").write_text("require('child_process');\n", encoding="utf-8")

    index = FileIndex.build(tmp_path)
    files = {f.relpath for f in index.files}
    assert "index.js.map" not in files
    assert {"bundle.min.js.map", "names.js.map", "payload.map"} <= files
    assert index.stats["skipped_source_map"] == 1


def test_node_finds_the_install_script_and_what_it_loads(tmp_path):
    # `node .` runs the package's main; `node install` runs install.js; a short script that
    # requires a minified module runs that module too.
    payload = "var a='" + "x" * 30_000 + "';" + _DROPPER
    _package(tmp_path / "dot", {"postinstall": "node ."})
    (tmp_path / "dot" / "package.json").write_text(
        json.dumps({"name": "dot", "version": "1.0.0", "main": "lib/main.js",
                    "scripts": {"postinstall": "node ."}}), encoding="utf-8")
    (tmp_path / "dot" / "lib").mkdir()
    (tmp_path / "dot" / "lib" / "main.js").write_text(payload, encoding="utf-8")

    _package(tmp_path / "bare", {"install": "node install"})
    (tmp_path / "bare" / "install.js").write_text(payload, encoding="utf-8")

    _package(tmp_path / "loads", {"postinstall": "node scripts/setup.js"})
    (tmp_path / "loads" / "scripts").mkdir()
    (tmp_path / "loads" / "scripts" / "setup.js").write_text(
        "const run = require('../vendor/run.min');\nrun();\n", encoding="utf-8")
    (tmp_path / "loads" / "vendor").mkdir()
    (tmp_path / "loads" / "vendor" / "run.min.js").write_text(payload, encoding="utf-8")

    for name in ("dot", "bare", "loads"):
        report = _analyze(tmp_path / name)
        assert report.verdict["has_malicious_indicators"], name


def test_a_require_that_leaves_the_package_is_not_followed(tmp_path):
    _package(tmp_path / "pkg", {"postinstall": "node setup.js"})
    (tmp_path / "pkg" / "setup.js").write_text("require('../outside.js');\n", encoding="utf-8")
    (tmp_path / "outside.js").write_text(_DROPPER, encoding="utf-8")
    from skilltotal.engine import _install_script_files

    assert _install_script_files(tmp_path / "pkg") == {"setup.js": "postinstall"}
