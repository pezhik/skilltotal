"""Release hygiene: docs that ship with a release must match the code.

These run in CI and in the release gate (release.yml runs pytest before publishing),
so forgetting them blocks the tag instead of shipping a stale PyPI page.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import skilltotal

ROOT = Path(__file__).resolve().parent.parent

# Every documented `uses: <owner>/skilltotal@vX.Y.Z` pin in the repo.
_ACTION_PIN_RE = re.compile(r"uses:\s*[\w.-]+/skilltotal@v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)")


# Folders under the repo root that are not part of this checkout's sources.
_NOT_THIS_CHECKOUT = {".git", ".venv", "node_modules", ".claude"}


def test_changelog_has_section_for_current_version():
    # CHANGELOG.md must describe the version being released.
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"## [{skilltotal.__version__}]" in text, (
        f"CHANGELOG.md has no section for {skilltotal.__version__} - "
        "write the changelog before tagging a release."
    )


def test_readme_documents_pypi_install():
    # README.md IS the PyPI long description (pyproject readme=...): it is frozen into
    # the artifact at tag time, so its Install section must reflect the published package.
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "pipx install skilltotal" in text
    assert "pip install skilltotal" in text


def test_documented_action_pins_match_the_current_version():
    """Every copy-pasteable `uses: .../skilltotal@vX` pin must point at the version being released.

    README pins were kept current by the release step while examples/ was not, so the example
    workflow silently advertised v0.10.4 for 28 releases. A stale pin is worse than a wrong
    number in prose: it is copied verbatim into other people's CI.
    """
    stale: list[str] = []
    for path in sorted(ROOT.rglob("*")):
        if path.suffix not in {".md", ".yml", ".yaml"} or not path.is_file():
            continue
        # Parts relative to the repo: a checkout that itself lives under `.claude/worktrees/` must
        # still be scanned, while agent worktrees nested in this checkout (other branches, other
        # versions) must not be read as this release's pins (2026-10-19, a deploy gate failure).
        if set(path.relative_to(ROOT).parts) & _NOT_THIS_CHECKOUT:
            continue
        for match in _ACTION_PIN_RE.finditer(path.read_text(encoding="utf-8")):
            if match.group("version") != skilltotal.__version__:
                stale.append(f"{path.relative_to(ROOT)}: @v{match.group('version')}")
    assert not stale, (
        f"action pins must be v{skilltotal.__version__}, found stale: {', '.join(stale)}"
    )


def test_documented_install_pins_match_the_current_version():
    """The CI recipes install `skilltotal==X`; X must be the version being released.

    Those lines are copied into GitLab and Jenkins pipelines as they stand, like the action pins.
    The README keeps one; the full recipes live in docs/ci.md.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert re.search(r"skilltotal==\d", readme), (
        "README's CI recipe is expected to pin skilltotal==<version>")
    stale: list[str] = []
    for path in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]:
        for version in re.findall(r"skilltotal==(\d+\.\d+\.\d+)", path.read_text(encoding="utf-8")):
            if version != skilltotal.__version__:
                stale.append(f"{path.relative_to(ROOT)}: {version}")
    assert not stale, f"install pins must be {skilltotal.__version__}, found {stale}"


def test_documented_npx_commands_name_the_current_release():
    """A plain `npx skilltotal` inside a repository runs that repository's
    `node_modules/.bin/skilltotal` if it has one, so the docs name the package with
    `--package=skilltotal@X`, and X is the version being released."""
    for doc in ("README.md", "npm/README.md", "docs/cli.md", "docs/mcp-server.md"):
        text = (ROOT / doc).read_text(encoding="utf-8")
        assert not re.search(r"npx\s+(?:-y\s+)?skilltotal\s+(?:scan|mcp|guard|diff|inventory)\b"
                             r"|\"-y\",\s*\"skilltotal\"", text), doc
        pins = re.findall(r"--package=skilltotal@(\d+\.\d+\.\d+)", text)
        assert pins, f"{doc} is expected to show the npx form with --package"
        stale = sorted({v for v in pins if v != skilltotal.__version__})
        assert not stale, f"{doc} npx pins must be {skilltotal.__version__}, found {stale}"


def test_efficacy_report_is_regenerated_for_this_release():
    """README says the detection-efficacy report is regenerated every release; hold it to that.

    The published report sat at engine 0.56.0 through five releases while README quoted it, so
    the report must name the version and ruleset being released, and README must quote its counts.
    """
    report = json.loads((ROOT / "docs" / "efficacy-report.json").read_text(encoding="utf-8"))
    regenerate = "regenerate: python tests/manual_eval/efficacy.py --out docs/efficacy-report"
    assert report["engine_version"] == skilltotal.__version__, (
        f"docs/efficacy-report.json is for engine {report['engine_version']}, "
        f"not {skilltotal.__version__}; {regenerate}"
    )
    assert report["ruleset_version"] == skilltotal.RULESET_VERSION, (
        f"docs/efficacy-report.json is for ruleset {report['ruleset_version']}, "
        f"not {skilltotal.RULESET_VERSION}; {regenerate}"
    )
    # The site says the same engine on the same Python version gives the same numbers; the report
    # has to say which Python that was, or nobody can check it.
    assert report.get("python_version"), f"docs/efficacy-report.json names no Python; {regenerate}"
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    counts = f"{report['positives']} malicious and {report['negatives']} benign samples"
    assert counts in readme, f"README must quote the efficacy report's sample counts: {counts!r}"


def test_schema_id_matches_report_schema_version():
    schema = (ROOT / "docs" / "report.schema.json").read_text(encoding="utf-8")
    assert f"report-{skilltotal.REPORT_SCHEMA_VERSION}.json" in schema, (
        "docs/report.schema.json $id does not match REPORT_SCHEMA_VERSION"
    )
    # The id once pointed at skilltotal.dev, a domain the project does not own. A schema id on
    # someone else's domain lets them publish a "canonical" schema for our reports.
    assert '"$id": "https://www.skilltotal.ai/schemas/' in schema, (
        "docs/report.schema.json $id must be on the project's own domain, www.skilltotal.ai"
    )


# Stdlib names that only exist from 3.11 on. `requires-python = ">=3.10"` is a promise, and
# nothing in the toolchain checks it: ruff has no rule for "this symbol postdates target-version",
# and a developer on 3.11+ sees a green local run. The one thing that catches it is the 3.10 CI
# matrix leg -- which went red for 17 days without being noticed, so assert it here as well, where
# a failure names the cause instead of a bare ImportError during collection.
_POST_310_STDLIB = {
    "datetime": {"UTC"},
    "asyncio": {"TaskGroup", "Runner"},
    "enum": {"StrEnum", "ReprEnum"},
    "typing": {"Self", "LiteralString", "Never", "TypeVarTuple", "assert_type", "assert_never"},
    "builtins": {"ExceptionGroup", "BaseExceptionGroup"},
}


def test_no_stdlib_names_newer_than_the_supported_python():
    import ast

    offenders: list[str] = []
    for path in sorted(ROOT.rglob("*.py")):
        parts = set(path.relative_to(ROOT).parts)
        # manual_eval/corpus is third-party source fetched by the calibration harness.
        if parts & _NOT_THIS_CHECKOUT or "corpus" in parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue  # eval-corpus samples are deliberately malformed in places
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            new_names = _POST_310_STDLIB.get(node.module or "", set())
            for alias in node.names:
                if alias.name in new_names:
                    offenders.append(
                        f"{path.relative_to(ROOT)}:{node.lineno} "
                        f"from {node.module} import {alias.name}"
                    )
    assert not offenders, (
        "these names do not exist on Python 3.10, which pyproject still supports: "
        + "; ".join(offenders)
    )


# Stdlib modules newer than the oldest supported Python: `sys.stdlib_module_names` on 3.10 does not
# list them, and the engine imports each one under `try`, with a fallback.
_STDLIB_AFTER_310 = {"tomllib"}


def test_the_engine_has_no_runtime_dependencies():
    """Zero runtime dependencies is a promise the README and pyproject make: pyproject declares
    none, and every module the package imports is the standard library or the package itself. A
    third-party import would install cleanly from a dev checkout and fail on a customer's
    machine."""
    import ast
    import sys

    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10: read the one line instead
        match = re.search(r"^dependencies\s*=\s*\[(.*?)\]", (ROOT / "pyproject.toml").read_text(
            encoding="utf-8"), flags=re.M | re.S)
        assert match, "pyproject.toml declares no `dependencies` list"
        assert not re.sub(r"#.*", "", match.group(1)).strip(), "pyproject declares dependencies"
    else:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        assert project["dependencies"] == [], f"runtime dependencies: {project['dependencies']}"

    allowed = set(sys.stdlib_module_names) | _STDLIB_AFTER_310 | {"skilltotal", "__future__"}
    offenders: list[str] = []
    for path in sorted((ROOT / "skilltotal").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            else:
                continue  # a relative import stays inside the package
            for name in names:
                if name.split(".")[0] not in allowed:
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} imports {name}")
    assert not offenders, "the engine must import only the standard library: " + "; ".join(
        offenders)
