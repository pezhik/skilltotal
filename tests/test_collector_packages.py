"""npm / PyPI source collection: classification, name parsing, safe extraction."""

from __future__ import annotations

import io
import json
import tarfile
import zipfile

import pytest

from skilltotal import collector
from skilltotal.collector import CollectionError


def _tgz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def test_classify_source():
    assert collector.classify_source("npm:lodash") == "npm"
    assert collector.classify_source("pypi:requests") == "pypi"
    assert collector.classify_source("https://www.npmjs.com/package/@scope/x") == "npm"
    assert collector.classify_source("https://pypi.org/project/flask/") == "pypi"
    assert collector.classify_source("https://github.com/a/b") == "git"
    assert collector.classify_source("/tmp/x") == "local"


def test_name_parsing_rejects_traversal():
    assert collector.npm_package_name("npm:@scope/pkg") == "@scope/pkg"
    assert collector.npm_package_name("npm:lodash") == "lodash"
    assert collector.npm_package_name("npm:../evil") is None
    assert collector.pypi_package_name("pypi:requests") == "requests"
    assert collector.pypi_package_name("pypi:../evil") is None


def test_tar_extraction_blocks_traversal(tmp_path):
    with pytest.raises(CollectionError):
        collector._safe_extract_tar(_tgz({"../evil.txt": b"x"}), tmp_path)


def test_zip_extraction_blocks_traversal(tmp_path):
    with pytest.raises(CollectionError):
        collector._safe_extract_zip(_zip({"../evil.txt": "x"}), tmp_path)


def test_collect_npm_resolves_latest_and_extracts(monkeypatch):
    registry = json.dumps(
        {
            "dist-tags": {"latest": "1.2.3"},
            "versions": {"1.2.3": {"dist": {"tarball": "https://registry.npmjs.org/x/-/x-1.2.3.tgz"}}},
        }
    ).encode()
    tarball = _tgz({"package/package.json": b'{"name":"x","version":"1.2.3"}', "package/index.js": b"1;"})
    monkeypatch.setattr(collector, "_http_get", lambda url: tarball if url.endswith(".tgz") else registry)

    with collector.collect("npm:x") as ctx:
        assert (ctx.root / "package.json").exists()
        assert ctx.component.type == "npm_package"
        assert ctx.component.version == "1.2.3"


def test_collect_pypi_prefers_sdist_and_extracts(monkeypatch):
    meta = json.dumps(
        {
            "info": {"version": "2.0.0"},
            "urls": [
                {"packagetype": "sdist", "filename": "x-2.0.0.tar.gz", "url": "https://files.pythonhosted.org/x-2.0.0.tar.gz"}
            ],
        }
    ).encode()
    sdist = _tgz({"x-2.0.0/pyproject.toml": b'[project]\nname="x"\nversion="2.0.0"\n', "x-2.0.0/x.py": b"y=1\n"})
    monkeypatch.setattr(collector, "_http_get", lambda url: sdist if url.endswith(".tar.gz") else meta)

    with collector.collect("pypi:x") as ctx:
        assert (ctx.root / "pyproject.toml").exists()
        assert ctx.component.type == "python_package"
        assert ctx.component.version == "2.0.0"
