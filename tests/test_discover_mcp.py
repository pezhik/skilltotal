"""Offline, deterministic tests for the MCP-registry manifest-discovery harness."""

from __future__ import annotations

import csv
import importlib.util
import sys
from pathlib import Path

_DM = Path(__file__).parent / "manual_eval" / "discover_mcp.py"
_spec = importlib.util.spec_from_file_location("discover_mcp", _DM)
dm = importlib.util.module_from_spec(_spec)
sys.modules["discover_mcp"] = dm  # register before exec so dataclass annotations resolve
_spec.loader.exec_module(dm)


# --- normalize_entry -------------------------------------------------------------------------


def test_normalize_prefers_npm_package():
    item = {
        "server": {
            "name": "com.x/remote-filesystem",
            "packages": [{"registryType": "npm", "identifier": "remote-fs-mcp", "version": "1"}],
        }
    }
    c = dm.normalize_entry(item)
    assert (c.source, c.ecosystem, c.type, c.name) == (
        "npm:remote-fs-mcp",
        "npm",
        "mcp",
        "remote-filesystem",
    )


def test_normalize_pypi_package():
    item = {
        "server": {
            "name": "io.github.o/srv",
            "packages": [{"registryType": "pypi", "identifier": "mcp-srv", "version": "1"}],
        }
    }
    c = dm.normalize_entry(item)
    assert c.source == "pypi:mcp-srv"
    assert (c.ecosystem, c.type, c.name) == ("pypi", "mcp", "srv")


def test_normalize_falls_back_to_github_repo():
    item = {
        "server": {
            "name": "io.github.o/srv",
            "repository": {"url": "https://github.com/o/srv", "source": "github"},
        }
    }
    c = dm.normalize_entry(item)
    assert (c.source, c.ecosystem, c.type) == ("https://github.com/o/srv", "git", "mcp")


def test_normalize_skips_when_no_usable_coordinate():
    remotes = {"server": {"name": "x/y", "remotes": [{"type": "sse", "url": "https://h"}]}}
    oci = {"server": {"name": "x/y", "packages": [{"registryType": "oci", "identifier": "img"}]}}
    assert dm.normalize_entry(remotes) is None
    assert dm.normalize_entry(oci) is None
    assert dm.normalize_entry({"server": {}}) is None
    assert dm.normalize_entry({}) is None


# --- hygiene + dedup -------------------------------------------------------------------------


def test_hygiene_rejects_forbidden_token():
    bad_path = dm.Candidate("https://github.com/x/Yandex.Disk", "git", "mcp", "y")
    bad_token = dm.Candidate("npm:x", "npm", "mcp", "12345678:ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    good = dm.Candidate("npm:safe", "npm", "mcp", "safe")
    assert not dm.hygiene_ok(bad_path)
    assert not dm.hygiene_ok(bad_token)
    assert dm.hygiene_ok(good)


def test_dedup_filters_existing_and_within_run():
    a = dm.Candidate("npm:a", "npm", "mcp", "a")
    b = dm.Candidate("npm:b", "npm", "mcp", "b")
    out = dm.dedup([a, b, a], {"npm:a"})
    assert [c.source for c in out] == ["npm:b"]


# --- select_new ------------------------------------------------------------------------------


def _c(name):
    return dm.Candidate(f"npm:{name}", "npm", "mcp", name)


def test_select_new_sorts_and_caps():
    chosen = dm.select_new(
        [_c("c"), _c("a"), _c("b")],
        set(),
        current_count=0,
        max_new=2,
        max_tries=10,
        manifest_cap=200,
        analyze=lambda s: object(),
    )
    assert [c.name for c in chosen] == ["a", "b"]  # deterministic order, capped at max_new


def test_select_new_respects_manifest_cap():
    chosen = dm.select_new(
        [_c("a")],
        set(),
        current_count=200,
        max_new=5,
        max_tries=10,
        manifest_cap=200,
        analyze=lambda s: object(),
    )
    assert chosen == []


def test_select_new_drops_unresolvable():
    def fake(s):
        if s == "npm:bad":
            raise dm.CollectionError("nope")
        return object()

    chosen = dm.select_new(
        [_c("bad"), _c("ok")],
        set(),
        current_count=0,
        max_new=5,
        max_tries=10,
        manifest_cap=200,
        analyze=fake,
    )
    assert [c.source for c in chosen] == ["npm:ok"]


def test_select_new_excludes_existing_and_unhygienic():
    cands = [_c("a"), dm.Candidate("npm:Yandex.Disk", "npm", "mcp", "bad"), _c("dup")]
    chosen = dm.select_new(
        cands,
        {"npm:dup"},
        current_count=0,
        max_new=5,
        max_tries=10,
        manifest_cap=200,
        analyze=lambda s: object(),
    )
    assert [c.name for c in chosen] == ["a"]


# --- manifest CSV I/O ------------------------------------------------------------------------


def _seed_manifest(tmp_path):
    p = tmp_path / "m.csv"
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["source", "ecosystem", "type", "name"])
        w.writerow(["npm:x", "npm", "mcp", "x"])
    return p


def test_append_round_trip_preserves_existing(tmp_path):
    p = _seed_manifest(tmp_path)
    dm.append_rows(p, [dm.Candidate("npm:y", "npm", "mcp", "y")])
    rows = list(csv.DictReader(open(p, newline="", encoding="utf-8-sig")))
    assert [r["source"] for r in rows] == ["npm:x", "npm:y"]
    assert [r["name"] for r in rows] == ["x", "y"]
    assert dm.load_existing_sources(p) == {"npm:x", "npm:y"}
    assert dm.count_rows(p) == 2


def test_append_rows_noop_on_empty(tmp_path):
    p = _seed_manifest(tmp_path)
    dm.append_rows(p, [])
    assert dm.count_rows(p) == 1


# --- main (resilient wiring) -----------------------------------------------------------------


def _npm_item(name, ident):
    return {
        "server": {
            "name": name,
            "packages": [{"registryType": "npm", "identifier": ident, "version": "1"}],
        }
    }


def test_main_dry_run_does_not_write(tmp_path, monkeypatch, capsys):
    p = _seed_manifest(tmp_path)
    monkeypatch.setattr(dm, "fetch_registry", lambda **k: [_npm_item("a/new", "new-pkg")])
    monkeypatch.setattr(dm, "resolvable", lambda s, analyze=dm.engine.analyze: True)
    rc = dm.main(["--manifest", str(p), "--dry-run"])
    assert rc == 0
    assert dm.count_rows(p) == 1  # unchanged
    assert "new-pkg" in capsys.readouterr().out


def test_main_appends_resolvable_new(tmp_path, monkeypatch):
    p = _seed_manifest(tmp_path)
    monkeypatch.setattr(
        dm, "fetch_registry", lambda **k: [_npm_item("a/new", "new-pkg"), _npm_item("a/x", "x")]
    )
    monkeypatch.setattr(dm, "resolvable", lambda s, analyze=dm.engine.analyze: True)
    rc = dm.main(["--manifest", str(p), "--max-new", "5"])
    assert rc == 0
    assert dm.load_existing_sources(p) == {"npm:x", "npm:new-pkg"}  # only the new one added


def test_main_exit_zero_on_fetch_failure(tmp_path, monkeypatch):
    p = _seed_manifest(tmp_path)

    def boom(**k):
        raise dm.URLError("down")

    monkeypatch.setattr(dm, "fetch_registry", boom)
    rc = dm.main(["--manifest", str(p)])
    assert rc == 0
    assert dm.count_rows(p) == 1  # nothing added, no crash
