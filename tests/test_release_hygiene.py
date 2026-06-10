"""Release hygiene: docs that ship with a release must match the code.

These run in CI and in the release gate (release.yml runs pytest before publishing),
so forgetting them blocks the tag instead of shipping a stale PyPI page.
"""

from __future__ import annotations

from pathlib import Path

import skilltotal

ROOT = Path(__file__).resolve().parent.parent


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


def test_schema_id_matches_report_schema_version():
    schema = (ROOT / "docs" / "report.schema.json").read_text(encoding="utf-8")
    assert f"report-{skilltotal.REPORT_SCHEMA_VERSION}.json" in schema, (
        "docs/report.schema.json $id does not match REPORT_SCHEMA_VERSION"
    )
