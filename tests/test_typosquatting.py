"""Package-name typosquatting detection (ST-TYPOSQUAT), offline and deterministic."""

from __future__ import annotations

from pathlib import Path

from skilltotal import engine
from skilltotal import typosquatting as ts


def _ids(report):
    return [f.id for f in report.findings]


def _npm_pkg(tmp_path: Path, name: str) -> Path:
    pkg = tmp_path / name
    pkg.mkdir()
    (pkg / "package.json").write_text(f'{{"name": "{name}", "version": "1.0.0"}}', encoding="utf-8")
    (pkg / "index.js").write_text("module.exports = {}\n", encoding="utf-8")
    return pkg


def _pypi_pkg(tmp_path: Path, name: str) -> Path:
    pkg = tmp_path / name
    pkg.mkdir()
    (pkg / "pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "1.0.0"\n', encoding="utf-8"
    )
    (pkg / "mod.py").write_text("x = 1\n", encoding="utf-8")
    return pkg


def test_levenshtein_bounded():
    assert ts._levenshtein("lodash", "loddash", 2) == 1
    assert ts._levenshtein("requests", "reqests", 2) == 1
    assert ts._levenshtein("lodash", "lodash", 2) == 0
    assert ts._levenshtein("lodash", "completelydifferent", 2) is None  # exceeds max_d


def test_npm_typosquat_flagged_with_manifest_evidence(tmp_path):
    report = engine.analyze(str(_npm_pkg(tmp_path, "loddash")))  # 1 edit from "lodash"
    assert "ST-TYPOSQUAT" in _ids(report)
    f = next(f for f in report.findings if f.id == "ST-TYPOSQUAT")
    assert f.evidence, "typosquat finding must carry evidence"
    assert f.evidence[0].file.lower().endswith("package.json")
    assert "AST02" in f.owasp  # mapped to supply-chain category


def test_pypi_typosquat_flagged(tmp_path):
    report = engine.analyze(str(_pypi_pkg(tmp_path, "reqests")))  # 1 edit from "requests"
    assert "ST-TYPOSQUAT" in _ids(report)


def test_exact_popular_name_not_flagged(tmp_path):
    assert "ST-TYPOSQUAT" not in _ids(engine.analyze(str(_npm_pkg(tmp_path, "lodash"))))
    assert "ST-TYPOSQUAT" not in _ids(engine.analyze(str(_pypi_pkg(tmp_path, "requests"))))


def test_short_name_not_flagged(tmp_path):
    # Names below the length floor (< 5) are skipped — too short to disambiguate from collisions.
    assert "ST-TYPOSQUAT" not in _ids(engine.analyze(str(_npm_pkg(tmp_path, "axi"))))


def test_scoped_npm_name_not_flagged(tmp_path):
    # Scoped names are namespace-protected; the bare segment must not be typosquat-matched.
    pkg = tmp_path / "scoped"
    pkg.mkdir()
    (pkg / "package.json").write_text(
        '{"name": "@acme/loddash", "version": "1.0.0"}', encoding="utf-8"
    )
    (pkg / "index.js").write_text("module.exports = {}\n", encoding="utf-8")
    assert "ST-TYPOSQUAT" not in _ids(engine.analyze(str(pkg)))


def test_non_package_component_not_flagged(tmp_path):
    d = tmp_path / "loddash-notes"
    d.mkdir()
    (d / "readme.txt").write_text("just notes\n", encoding="utf-8")
    assert "ST-TYPOSQUAT" not in _ids(engine.analyze(str(d)))


def test_unrelated_name_not_flagged(tmp_path):
    pkg = _npm_pkg(tmp_path, "my-internal-widget-kit")
    assert "ST-TYPOSQUAT" not in _ids(engine.analyze(str(pkg)))


def test_popular_crypto_names_are_exact_matches_not_flagged(tmp_path):
    """Regression (tripwire): PyNaCl (2 edits from pyyaml) and authlib (1 edit from oauthlib)
    are themselves popular packages; with them in the curated list the exact-match exemption
    applies (case/PEP 503-normalized)."""
    assert "ST-TYPOSQUAT" not in _ids(engine.analyze(str(_pypi_pkg(tmp_path, "PyNaCl"))))


def test_authlib_not_flagged(tmp_path):
    assert "ST-TYPOSQUAT" not in _ids(engine.analyze(str(_pypi_pkg(tmp_path, "authlib"))))


def test_near_miss_of_pynacl_flagged(tmp_path):
    # Adding pynacl to the list also protects it: a 1-edit impersonation now fires.
    assert "ST-TYPOSQUAT" in _ids(engine.analyze(str(_pypi_pkg(tmp_path, "pynacll"))))
