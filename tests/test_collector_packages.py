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


def test_version_spec_parsing():
    # npm: trailing @version is a pin; the leading scope @ is not.
    assert collector.npm_package_spec("npm:lodash@4.17.21") == ("lodash", "4.17.21")
    assert collector.npm_package_spec("npm:@scope/pkg@1.0.0") == ("@scope/pkg", "1.0.0")
    assert collector.npm_package_spec("npm:@scope/pkg") == ("@scope/pkg", None)
    assert collector.npm_package_spec("npm:lodash") == ("lodash", None)
    # pypi: == and @ both pin.
    assert collector.pypi_package_spec("pypi:requests==2.31.0") == ("requests", "2.31.0")
    assert collector.pypi_package_spec("pypi:requests@2.31.0") == ("requests", "2.31.0")
    assert collector.pypi_package_spec("pypi:requests") == ("requests", None)


def test_collect_npm_pinned_version(monkeypatch):
    registry = json.dumps(
        {
            "dist-tags": {"latest": "2.0.0"},
            "versions": {
                "1.2.3": {"dist": {"tarball": "https://registry.npmjs.org/x/-/x-1.2.3.tgz"}},
                "2.0.0": {"dist": {"tarball": "https://registry.npmjs.org/x/-/x-2.0.0.tgz"}},
            },
        }
    ).encode()
    tarball = _tgz(
        {"package/package.json": b'{"name":"x","version":"1.2.3"}', "package/index.js": b"1;"}
    )
    monkeypatch.setattr(
        collector, "_http_get",
        lambda url: tarball if url.endswith("x-1.2.3.tgz") else registry,
    )
    with collector.collect("npm:x@1.2.3") as ctx:
        assert ctx.component.version == "1.2.3"  # pinned, not latest 2.0.0


def test_collect_npm_unknown_version_errors(monkeypatch):
    registry = json.dumps(
        {"dist-tags": {"latest": "2.0.0"},
         "versions": {"2.0.0": {"dist": {"tarball": "https://r/x-2.0.0.tgz"}}}}
    ).encode()
    monkeypatch.setattr(collector, "_http_get", lambda url: registry)
    with pytest.raises(CollectionError):
        with collector.collect("npm:x@9.9.9"):
            pass


def test_collect_pypi_pinned_version(monkeypatch):
    meta = json.dumps(
        {
            "info": {"version": "1.5.0"},
            "urls": [
                {"packagetype": "sdist", "filename": "x-1.5.0.tar.gz",
                 "url": "https://files.pythonhosted.org/x-1.5.0.tar.gz"}
            ],
        }
    ).encode()
    sdist = _tgz({"x-1.5.0/pyproject.toml": b'[project]\nname="x"\nversion="1.5.0"\n'})
    seen = {}

    def fake_get(url):
        seen["url"] = url
        return sdist if url.endswith(".tar.gz") else meta

    monkeypatch.setattr(collector, "_http_get", fake_get)
    with collector.collect("pypi:x==1.5.0") as ctx:
        assert ctx.component.version == "1.5.0"


def test_tar_extraction_blocks_traversal(tmp_path):
    with pytest.raises(CollectionError):
        collector._safe_extract_tar(_tgz({"../evil.txt": b"x"}), tmp_path)


def test_zip_extraction_blocks_traversal(tmp_path):
    with pytest.raises(CollectionError):
        collector._safe_extract_zip(_zip({"../evil.txt": "x"}), tmp_path)


def test_tar_extraction_blocks_sibling_prefix_escape(tmp_path):
    # A sibling dir sharing a name prefix (dest 'pkg' vs 'pkg-evil') would fool a
    # str.startswith check; boundary-correct relative_to must still reject it.
    dest = tmp_path / "pkg"
    dest.mkdir()
    with pytest.raises(CollectionError):
        collector._safe_extract_tar(_tgz({"../pkg-evil/x.txt": b"x"}), dest)


def test_zip_extraction_skips_symlinks(tmp_path):
    dest = tmp_path / "z"
    dest.mkdir()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        link = zipfile.ZipInfo("link")
        link.external_attr = (0xA1FF) << 16  # S_IFLNK | perms
        zf.writestr(link, "/etc/passwd")
        zf.writestr("normal.txt", "ok")
    collector._safe_extract_zip(buf.getvalue(), dest)
    assert (dest / "normal.txt").exists()
    assert not (dest / "link").exists()  # symlink entry was skipped


def test_collect_npm_resolves_latest_and_extracts(monkeypatch):
    registry = json.dumps(
        {
            "dist-tags": {"latest": "1.2.3"},
            "versions": {"1.2.3": {"dist": {"tarball": "https://registry.npmjs.org/x/-/x-1.2.3.tgz"}}},
        }
    ).encode()
    tarball = _tgz(
        {"package/package.json": b'{"name":"x","version":"1.2.3"}', "package/index.js": b"1;"}
    )
    monkeypatch.setattr(
        collector, "_http_get", lambda url: tarball if url.endswith(".tgz") else registry
    )

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
    sdist = _tgz(
        {
            "x-2.0.0/pyproject.toml": b'[project]\nname="x"\nversion="2.0.0"\n',
            "x-2.0.0/x.py": b"y=1\n",
        }
    )
    monkeypatch.setattr(
        collector, "_http_get", lambda url: sdist if url.endswith(".tar.gz") else meta
    )

    with collector.collect("pypi:x") as ctx:
        assert (ctx.root / "pyproject.toml").exists()
        assert ctx.component.type == "python_package"
        assert ctx.component.version == "2.0.0"
        # the analyzed distribution URL is surfaced for source deep-linking (schema 1.2)
        assert ctx.component.download_url == "https://files.pythonhosted.org/x-2.0.0.tar.gz"
        assert ctx.component.to_dict()["download_url"] == ctx.component.download_url


def test_git_clone_timeout_becomes_collection_error(monkeypatch, tmp_path):
    """A hung/slow clone (subprocess timeout) surfaces as a clean CollectionError, not a hang."""
    import subprocess

    monkeypatch.setattr(collector, "_reject_if_too_large", lambda _u: None)  # no network

    class _Proc:
        returncode = None

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

        def communicate(self, timeout=None):
            if timeout is not None:  # the time-bounded clone wait -> simulate it expiring
                raise subprocess.TimeoutExpired(cmd="git clone", timeout=timeout)
            return ("", "")  # the post-kill drain

    def fake_popen(args, **kwargs):
        # The clone runs non-interactively (no credential prompt that could hang).
        assert kwargs.get("env", {}).get("GIT_TERMINAL_PROMPT") == "0"
        return _Proc()

    monkeypatch.setattr(collector.subprocess, "Popen", fake_popen)
    with pytest.raises(CollectionError, match="timed out"):
        collector.collect("https://github.com/owner/repo")
