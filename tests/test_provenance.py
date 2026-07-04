"""Provenance signals: pure metadata evaluation, source dispatch, and the CLI flag."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from skilltotal.cli import EXIT_OK, main
from skilltotal.provenance import (
    ProvenanceError,
    collect_provenance,
    signals_from_npm,
    signals_from_pypi,
)

NOW = datetime(2026, 7, 4, tzinfo=timezone.utc)


def _npm_meta(**overrides):
    meta = {
        "dist-tags": {"latest": "2.0.0"},
        "versions": {
            "2.0.0": {"repository": {"url": "https://github.com/x/y"}},
        },
        "time": {"2.0.0": "2025-01-01T00:00:00.000Z"},
    }
    meta.update(overrides)
    return meta


def _titles(signals):
    return {s.title for s in signals}


# --- npm ------------------------------------------------------------------------------

def test_npm_healthy_package_has_no_signals():
    assert signals_from_npm(_npm_meta(), None, now=NOW) == []


def test_npm_deprecated_and_no_repository():
    meta = _npm_meta(versions={"2.0.0": {"deprecated": "use other-pkg instead"}})
    titles = _titles(signals_from_npm(meta, None, now=NOW))
    assert "Deprecated on npm" in titles
    assert "No repository link" in titles


def test_npm_recently_published():
    meta = _npm_meta(time={"2.0.0": "2026-06-30T00:00:00.000Z"})
    signals = signals_from_npm(meta, None, now=NOW)
    assert "Recently published" in _titles(signals)
    assert "4 day(s) ago" in next(s for s in signals if s.title == "Recently published").reason


def test_npm_stale_latest_release():
    meta = _npm_meta(time={"2.0.0": "2020-01-01T00:00:00.000Z"})
    assert "No recent releases" in _titles(signals_from_npm(meta, None, now=NOW))


def test_npm_pinned_version_is_evaluated_not_latest():
    meta = _npm_meta(
        versions={
            "1.0.0": {"deprecated": "old line", "repository": "x"},
            "2.0.0": {"repository": "x"},
        },
        time={"1.0.0": "2024-01-01T00:00:00.000Z", "2.0.0": "2025-01-01T00:00:00.000Z"},
    )
    assert "Deprecated on npm" in _titles(signals_from_npm(meta, "1.0.0", now=NOW))
    assert signals_from_npm(meta, "2.0.0", now=NOW) == []


# --- pypi -----------------------------------------------------------------------------

def _pypi_meta(**overrides):
    meta = {
        "info": {
            "version": "2.0.0",
            "project_urls": {"Source": "https://github.com/x/y"},
        },
        "releases": {
            "2.0.0": [{"upload_time_iso_8601": "2025-01-01T00:00:00.000000Z"}],
        },
    }
    meta.update(overrides)
    return meta


def test_pypi_healthy_package_has_no_signals():
    assert signals_from_pypi(_pypi_meta(), None, now=NOW) == []


def test_pypi_yanked_and_recent_and_no_repo():
    meta = _pypi_meta(
        info={"version": "2.0.0", "project_urls": {}},
        releases={
            "2.0.0": [
                {
                    "upload_time_iso_8601": "2026-06-20T00:00:00.000000Z",
                    "yanked": True,
                    "yanked_reason": "broken sdist",
                }
            ]
        },
    )
    titles = _titles(signals_from_pypi(meta, None, now=NOW))
    assert titles == {"Yanked on PyPI", "Recently published", "No repository link"}


def test_pypi_stale_latest_release():
    meta = _pypi_meta(releases={"2.0.0": [{"upload_time_iso_8601": "2019-05-01T00:00:00Z"}]})
    assert "No recent releases" in _titles(signals_from_pypi(meta, None, now=NOW))


# --- dispatch -------------------------------------------------------------------------

def test_collect_provenance_non_registry_source_is_empty(tmp_path: Path):
    assert collect_provenance(str(tmp_path), now=NOW) == []


def test_collect_provenance_invalid_spec_raises():
    with pytest.raises(ProvenanceError):
        collect_provenance("npm:not a valid name!", now=NOW)


def test_collect_provenance_npm_uses_registry(monkeypatch):
    calls = []

    def fake_fetch(url):
        calls.append(url)
        return _npm_meta(versions={"2.0.0": {}}, time={"2.0.0": "2026-07-01T00:00:00Z"})

    monkeypatch.setattr("skilltotal.provenance._fetch", fake_fetch)
    signals = collect_provenance("npm:@scope/pkg", now=NOW)
    assert calls == ["https://registry.npmjs.org/@scope%2Fpkg"]
    assert "Recently published" in _titles(signals)
    assert all(s.category == "provenance" for s in signals)


# --- CLI ------------------------------------------------------------------------------

def test_cli_scan_provenance_appends_needs_review(tmp_path: Path, capsys, monkeypatch):
    root = tmp_path / "pkg"
    root.mkdir()
    (root / "index.js").write_text('console.log("hi");\n', encoding="utf-8")

    monkeypatch.setattr(
        "skilltotal.provenance._fetch",
        lambda url: pytest.fail("non-registry source must not hit the network"),
    )
    code = main(["scan", str(root), "--provenance", "--json"])
    out, err = capsys.readouterr()
    assert code == EXIT_OK
    data = json.loads(out)
    assert data["metadata"]["provenance_checked"] is True
    assert "only applies to npm:/pypi:" in err
