"""Release hygiene: docs that ship with a release must match the code.

These run in CI and in the release gate (release.yml runs pytest before publishing),
so forgetting them blocks the tag instead of shipping a stale PyPI page.
"""

from __future__ import annotations

import re
from pathlib import Path

import skilltotal

ROOT = Path(__file__).resolve().parent.parent

# Every documented `uses: <owner>/skilltotal@vX.Y.Z` pin in the repo.
_ACTION_PIN_RE = re.compile(r"uses:\s*[\w.-]+/skilltotal@v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)")


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
        if any(part in {".git", ".venv", "node_modules"} for part in path.parts):
            continue
        for match in _ACTION_PIN_RE.finditer(path.read_text(encoding="utf-8")):
            if match.group("version") != skilltotal.__version__:
                stale.append(f"{path.relative_to(ROOT)}: @v{match.group('version')}")
    assert not stale, (
        f"action pins must be v{skilltotal.__version__}, found stale: {', '.join(stale)}"
    )


def test_schema_id_matches_report_schema_version():
    schema = (ROOT / "docs" / "report.schema.json").read_text(encoding="utf-8")
    assert f"report-{skilltotal.REPORT_SCHEMA_VERSION}.json" in schema, (
        "docs/report.schema.json $id does not match REPORT_SCHEMA_VERSION"
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
        parts = set(path.parts)
        # manual_eval/corpus is third-party source fetched by the calibration harness.
        if parts & {".git", ".venv", "node_modules"} or "corpus" in parts:
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
