"""Research 2026-11-18: two PyPI install/import-time shapes, each paired with an honest look-alike.

Sanitized fixtures only (``.invalid``/``.test`` hosts, inert content).

* ``ST-PY-SETUP-HOST-BEACON`` -- setup.py install command reading user/host name and requesting.
* ``ST-PY-INIT-REMOTE-ARCHIVE-LOADER`` -- constructor that downloads, unpacks and runs an archive.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal.collector import detect_component
from skilltotal.engine import analyze_directory

_CORPUS = Path(__file__).resolve().parent / "eval_corpus"

_PAIRS = [
    ("ST-PY-SETUP-HOST-BEACON", "setup-host-beacon", "install-override-fingerprint",
     ["install-copies-data", "fetch-without-install-override"]),
    ("ST-PY-INIT-REMOTE-ARCHIVE-LOADER", "init-remote-archive-loader", "model-init-fetch-unpack",
     ["dataset-downloader-no-run", "installer-function-not-constructor"]),
]


def _report(root: Path):
    return analyze_directory(root, detect_component(root, source=str(root)))


def test_each_attack_flagged_and_lookalikes_clean():
    for rule_id, tech, pos, negs in _PAIRS:
        report = _report(_CORPUS / "positive" / "AST02" / tech / pos)
        finding = next((f for f in report.findings if f.id == rule_id), None)
        assert finding is not None, f"{rule_id} missed its positive"
        assert finding.evidence
        assert report.verdict.get("has_malicious_indicators") is True
        for neg in negs:
            clean = _report(_CORPUS / "negative" / "AST02" / tech / neg)
            assert rule_id not in {f.id for f in clean.findings}, f"{rule_id} fired on {neg}"


def test_comment_only_archive_url_is_silent(tmp_path):
    (tmp_path / "m.py").write_text(
        "# FIXTURE ONLY - synthetic detection test sample, not real malware\n"
        "import importlib\nimport zipfile\n"
        "# see https://github.invalid/acme/x/archive/main.zip\n"
        "class A:\n    def __init__(self):\n"
        "        zipfile.ZipFile('a.zip').extractall('d')\n"
        "        importlib.import_module('d')\n",
        encoding="utf-8",
    )
    assert "ST-PY-INIT-REMOTE-ARCHIVE-LOADER" not in {f.id for f in _report(tmp_path).findings}
