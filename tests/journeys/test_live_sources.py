"""A developer scans published packages and a GitHub repository by name, over the network.

Registries, PyPI's file layout, GitHub's archive and API answers, and git itself change under a
release that does not: these catch that. They need the network, so they run only when
SKILLTOTAL_JOURNEY_LIVE=1 (CI's weekly scheduled run). Every source is pinned to a version or a
commit, so the expected answer does not move.
"""

from __future__ import annotations

import json
import os

import pytest

from tests.journeys.conftest import needs_git

pytestmark = pytest.mark.skipif(os.environ.get("SKILLTOTAL_JOURNEY_LIVE") != "1",
                                reason="live network journeys run with SKILLTOTAL_JOURNEY_LIVE=1")

# github/gitignore: small, public, plain text; a commit is immutable.
_REPO = "https://github.com/github/gitignore"
_COMMIT = "0e5d690153ca3da8a4a1aef2d053406f408f531c"

SOURCES = [
    pytest.param("npm:left-pad@1.3.0", "1.3.0", id="npm"),
    pytest.param("pypi:six==1.16.0", "1.16.0", id="pypi"),
    pytest.param(f"{_REPO}/commit/{_COMMIT}", None, id="github-commit", marks=needs_git),
    pytest.param(f"{_REPO}/tree/{_COMMIT}/Global", None, id="github-subfolder", marks=needs_git),
]


@pytest.mark.parametrize(("source", "version"), SOURCES)
def test_a_pinned_live_source_scans(skilltotal, tmp_path, source, version):
    run = skilltotal("scan", source, "--json", "--output", str(tmp_path / "report.json"))
    assert run.code == 0, run.out + run.err
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["component"]["source"] == source
    if version:
        assert report["component"]["version"] == version
    assert report["metadata"]["files_indexed"] > 0

    sarif = skilltotal("scan", source, "--sarif")
    assert sarif.code == 0, sarif.err
    assert json.loads(sarif.out)["version"] == "2.1.0"
