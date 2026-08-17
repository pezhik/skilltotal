"""A published package ships its build output — scanning must not skip it.

`dist/` and `build/` are skipped for a repository, where they duplicate first-party source that
sits right next to them. A published npm tarball is the opposite case: the sources stay in git and
only the build output is shipped, so skipping it scanned nothing at all. Measured on the public
MCP registry, 11 of 12 sampled npm packages that reported ZERO findings were in fact shipping
shell execution, network egress or filesystem access inside `dist/`.
"""

from __future__ import annotations

from pathlib import Path

from skilltotal.engine import analyze_directory
from skilltotal.models import Component

_SHELL_JS = """\
const { execSync } = require("child_process");
function run(cmd) { return execSync(cmd); }
module.exports = { run };
"""


def _package(tmp_path: Path) -> Path:
    """A tarball-shaped package: manifest plus build output, no sources (the usual npm shape)."""
    (tmp_path / "package.json").write_text(
        '{"name": "demo-mcp", "version": "1.0.0", "main": "dist/index.js"}', encoding="utf-8"
    )
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.js").write_text(_SHELL_JS, encoding="utf-8")
    return tmp_path


def _component(kind: str) -> Component:
    return Component(name="demo-mcp", type=kind, source="npm:demo-mcp", version="1.0.0")


def test_build_output_is_scanned_for_a_published_npm_package(tmp_path):
    report = analyze_directory(_package(tmp_path), _component("npm_package"))
    assert "ST-SHELL-NODE" in {f.id for f in report.findings}


def test_build_output_is_scanned_for_a_published_python_package(tmp_path):
    (tmp_path / "setup.py").write_text("from setuptools import setup\nsetup()\n", encoding="utf-8")
    build = tmp_path / "build"
    build.mkdir()
    (build / "run.py").write_text("import os\nos.system('id')\n", encoding="utf-8")
    report = analyze_directory(tmp_path, _component("python_package"))
    assert "ST-SHELL-PY" in {f.id for f in report.findings}


def test_build_output_stays_skipped_for_a_repository(tmp_path):
    """Unchanged for git/local sources: there dist/ duplicates source that is also present."""
    report = analyze_directory(_package(tmp_path), _component("directory"))
    assert "ST-SHELL-NODE" not in {f.id for f in report.findings}


def test_minified_bundle_is_reported_as_uncovered_rather_than_scanned(tmp_path):
    """A bundle cannot carry checkable evidence, so it is disclosed instead of scanned.

    Reporting "line 1" of a single 400 KB line would break the guarantee that every finding is
    verifiable, and the bundle's inlined dependencies are not the component's own code.
    """
    (tmp_path / "package.json").write_text('{"name": "b", "version": "1.0.0"}', encoding="utf-8")
    dist = tmp_path / "dist"
    dist.mkdir()
    bundle = 'var a=1;require("child_process").execSync("id");' + ("var pad=1;" * 4000)
    (dist / "bundle.js").write_text(bundle, encoding="utf-8")

    report = analyze_directory(tmp_path, _component("npm_package"))
    assert "ST-SHELL-NODE" not in {f.id for f in report.findings}
    coverage = [n for n in report.needs_review if n.title == "Minified bundle not analyzed"]
    assert coverage and "dist/bundle.js" in coverage[0].reason
    assert report.risk_score == 0  # needs_review never moves the score


def test_readable_build_output_is_still_scanned(tmp_path):
    """Transpiled (not minified) output is ordinary first-party code and must be analyzed."""
    (tmp_path / "package.json").write_text('{"name": "t", "version": "1.0.0"}', encoding="utf-8")
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.js").write_text(_SHELL_JS * 400, encoding="utf-8")  # large but line-broken
    report = analyze_directory(tmp_path, _component("npm_package"))
    assert "ST-SHELL-NODE" in {f.id for f in report.findings}
    assert not [n for n in report.needs_review if n.title == "Minified bundle not analyzed"]


def test_build_output_proves_capability_but_not_risk(tmp_path):
    """A bundle inlines tests, fixtures and pattern literals, so path-based demotion goes blind.

    Real packages produced `critical` verdicts this way: a security tool's own `"*id_rsa*"` watch
    list, a code generator's `JWT_ACCESS_SECRET: "test..."` scaffold, and a bundled SSRF assertion
    against 169.254.169.254. The capability is still true and stays; the risk claim is demoted.
    """
    (tmp_path / "package.json").write_text('{"name": "g", "version": "1.0.0"}', encoding="utf-8")
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "bundle.js").write_text(
        'const { execSync } = require("child_process");\n'
        'const watchlist = ["*id_rsa*", "~/.ssh/id_rsa"];\n'
        'const JWT_ACCESS_SECRET = "sk_test_51H8xKlAbCdEfGhIjKlMnOpQrStUvWxYz";\n'
        'fetch("https://example.invalid/collect");\n',
        encoding="utf-8",
    )
    report = analyze_directory(tmp_path, _component("npm_package"))
    ids = {f.id for f in report.findings}
    assert "ST-SHELL-NODE" in ids  # capability: the artifact really can do this
    assert "ST-SENS-PATH" not in ids  # risk claim from bundled context: demoted
    assert "ST-COMBO-EXFIL" not in ids  # ... so the synthesized combo cannot fire either
    assert any("build output" in n.reason for n in report.needs_review)


def test_demotion_only_touches_evidence_inside_build_output():
    """Scoped by path: the same rule keeps whatever it matched outside dist/.

    Asserted on the split function directly so the case is not masked by the other demotion
    layers (a bare string literal, for instance, is already demoted by the code-context pass).
    """
    from skilltotal.engine import _split_build_output_evidence
    from skilltotal.models import Evidence, Finding, Severity

    def _finding(rule_id: str, files: list[str]) -> Finding:
        return Finding(
            id=rule_id,
            severity=Severity.HIGH,
            category="test",
            title=rule_id,
            description="d",
            recommendation="r",
            evidence=[
                Evidence(file=f, line_start=1, line_end=1, snippet="x") for f in files
            ],
        )

    risky = _finding("ST-SECRET-EMBEDDED", ["dist/bundle.js", "src/config.js"])
    capability = _finding("ST-SHELL-NODE", ["dist/bundle.js"])
    kept, review = _split_build_output_evidence([risky, capability])

    kept_by_id = {f.id: f for f in kept}
    assert [e.file for e in kept_by_id["ST-SECRET-EMBEDDED"].evidence] == ["src/config.js"]
    assert [e.file for e in kept_by_id["ST-SHELL-NODE"].evidence] == ["dist/bundle.js"]
    assert len(review) == 1 and "build output" in review[0].reason


def test_minified_detection_ignores_small_and_non_code_files(tmp_path):
    """Narrow on purpose: a one-line JSON fixture or a short script must not be mistaken for one."""
    from skilltotal.file_index import _is_minified

    long_line = "x" * 30_000
    assert not _is_minified("data.json", long_line)      # not a code suffix
    assert not _is_minified("tiny.js", "a=1;" * 100)     # under the size floor
    assert not _is_minified("src.js", "a = 1;\n" * 5000)  # large but line-broken
    assert _is_minified("bundle.js", long_line)
