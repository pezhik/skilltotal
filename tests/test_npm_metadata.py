"""npm sources read one version's manifest from the registry, not the package's whole history.

The packument lists every version ever published: 31 MB for `next`, 16 MB for `typescript`. The
registry serves a single version or dist-tag at `/<name>/<version-or-tag>` in a few KB with the
same `version` and `dist.tarball`. Whatever that document cannot answer falls back to the
packument, so every outcome, error messages included, stays what it was.
"""

from __future__ import annotations

import io
import json
import re
import tarfile
import urllib.error

import pytest

from skilltotal import collector
from skilltotal.collector import CollectionError

REGISTRY = "https://registry.npmjs.org"


def _tgz(name: str, version: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = json.dumps({"name": name, "version": version}).encode()
        info = tarfile.TarInfo("package/package.json")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _http_error(url: str, code: int) -> CollectionError:
    err = CollectionError(f"failed to fetch {url}: HTTP Error {code}")
    err.__cause__ = urllib.error.HTTPError(url, code, "Not Found", None, None)  # type: ignore[arg-type]
    return err


def _registry(monkeypatch, docs: dict) -> list[str]:
    """Serve ``docs`` (url -> JSON document or an exception to raise) and every tarball; any other
    request fails the test."""
    seen: list[str] = []

    def fake_get(url: str) -> bytes:
        seen.append(url)
        tarball = re.search(r"/([^/]+?)-(\d[^/]*)\.tgz$", url)
        if tarball:
            return _tgz(*tarball.groups())
        if url not in docs:
            pytest.fail(f"unexpected request: {url}")
        doc = docs[url]
        if isinstance(doc, Exception):
            raise doc
        return json.dumps(doc).encode()

    monkeypatch.setattr(collector, "_http_get", fake_get)
    return seen


def _manifest(name: str, version: str) -> dict:
    tail = name.rsplit("/", 1)[-1]
    return {"name": name, "version": version,
            "dist": {"tarball": f"{REGISTRY}/{name}/-/{tail}-{version}.tgz"}}


@pytest.mark.parametrize(
    ("source", "url", "name", "version"),
    [
        ("npm:x", f"{REGISTRY}/x/latest", "x", "2.0.0"),
        ("npm:x@latest", f"{REGISTRY}/x/latest", "x", "2.0.0"),
        ("npm:x@next", f"{REGISTRY}/x/next", "x", "3.0.0-rc.1"),
        ("npm:x@1.2.3", f"{REGISTRY}/x/1.2.3", "x", "1.2.3"),
        ("https://www.npmjs.com/package/x", f"{REGISTRY}/x/latest", "x", "2.0.0"),
        # A scoped name is encoded exactly as for the packument (`@scope%2Fx`).
        ("npm:@scope/x@1.2.3", f"{REGISTRY}/@scope%2Fx/1.2.3", "@scope/x", "1.2.3"),
    ],
)
def test_one_version_manifest_is_fetched_not_the_packument(monkeypatch, source, url, name,
                                                         version):
    doc = _manifest(name, version)
    seen = _registry(monkeypatch, {url: doc})
    with collector.collect(source) as ctx:
        assert ctx.component.version == version
        assert ctx.component.download_url == doc["dist"]["tarball"]
        assert ctx.component.type == "npm_package"
    assert seen == [url, doc["dist"]["tarball"]]


def test_what_the_registry_does_not_have_fails_exactly_as_before(monkeypatch):
    packument = {"dist-tags": {"latest": "2.0.0"},
                 "versions": {"2.0.0": _manifest("x", "2.0.0")}}
    missing, a_range = f"{REGISTRY}/x/9.9.9", f"{REGISTRY}/x/%5E2.0.0"
    seen = _registry(monkeypatch, {missing: _http_error(missing, 404),
                                   a_range: _http_error(a_range, 404),
                                   f"{REGISTRY}/x": packument})
    with pytest.raises(CollectionError, match="has no version '9.9.9'"):
        with collector.collect("npm:x@9.9.9"):
            pass
    # A range is resolved by the installer, not the registry: it never was a scannable version.
    with pytest.raises(CollectionError, match=r"has no version '\^2\.0\.0'"):
        with collector.collect("npm:x@^2.0.0"):
            pass
    assert seen[-1] == f"{REGISTRY}/x"


def test_a_package_the_registry_does_not_have_fails_exactly_as_before(monkeypatch):
    missing = _http_error(f"{REGISTRY}/nope", 404)
    _registry(monkeypatch, {f"{REGISTRY}/nope/latest": _http_error(f"{REGISTRY}/nope/latest", 404),
                            f"{REGISTRY}/nope": missing})
    with pytest.raises(CollectionError) as caught:
        with collector.collect("npm:nope"):
            pass
    assert caught.value is missing


def test_a_manifest_that_disagrees_with_the_pin_is_not_trusted(monkeypatch):
    packument = {"dist-tags": {"latest": "1.2.3"}, "versions": {"1.2.3": _manifest("x", "1.2.3")}}
    seen = _registry(monkeypatch, {f"{REGISTRY}/x/1.2.3": _manifest("x", "9.9.9"),
                                   f"{REGISTRY}/x": packument})
    with collector.collect("npm:x@1.2.3") as ctx:
        assert ctx.component.version == "1.2.3"
    assert seen[:2] == [f"{REGISTRY}/x/1.2.3", f"{REGISTRY}/x"]


def test_an_unreachable_registry_is_not_asked_twice(monkeypatch):
    offline = CollectionError(f"failed to fetch {REGISTRY}/x/latest: <urlopen error offline>")
    offline.__cause__ = urllib.error.URLError("offline")
    seen = _registry(monkeypatch, {f"{REGISTRY}/x/latest": offline})
    with pytest.raises(CollectionError, match="failed to fetch"):
        with collector.collect("npm:x"):
            pass
    assert seen == [f"{REGISTRY}/x/latest"]


def test_a_registry_answer_that_is_not_json_is_a_collection_error(monkeypatch):
    monkeypatch.setattr(collector, "_http_get", lambda url: b"<html>maintenance</html>")
    with pytest.raises(CollectionError):
        with collector.collect("npm:x"):
            pass
    with pytest.raises(CollectionError):
        with collector.collect("pypi:x"):
            pass
