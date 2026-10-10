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


@pytest.mark.parametrize(("tag", "expected"), [("latest", "2.0.0"), ("next", "3.0.0-rc.1")])
def test_collect_npm_resolves_a_dist_tag(monkeypatch, tag, expected):
    # `npx -y @playwright/mcp@latest` is how MCP servers are usually installed: the tag names the
    # version npm would fetch, it is not a missing version.
    registry = json.dumps(
        {
            "dist-tags": {"latest": "2.0.0", "next": "3.0.0-rc.1"},
            "versions": {
                v: {"dist": {"tarball": f"https://registry.npmjs.org/x/-/x-{v}.tgz"}}
                for v in ("1.2.3", "2.0.0", "3.0.0-rc.1")
            },
        }
    ).encode()

    def fake_get(url):
        if url.endswith(".tgz"):
            version = url.rsplit("x-", 1)[1][: -len(".tgz")]
            return _tgz({"package/package.json": json.dumps({"name": "x", "version": version})
                         .encode()})
        return registry

    monkeypatch.setattr(collector, "_http_get", fake_get)
    with collector.collect(f"npm:x@{tag}") as ctx:
        assert ctx.component.version == expected


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_resolve_release_pins_what_the_registry_serves_now(monkeypatch):
    urls = []
    pypi = {"info": {"version": "2.32.3"},
            "urls": [_dist("sdist", "requests-2.32.3.tar.gz"),
                     _dist("bdist_wheel", "requests-2.32.3-py3-none-any.whl")]}

    def fake_open(url, *, timeout):
        urls.append(url)
        if url.startswith("https://registry.npmjs.org/"):
            return _Resp(json.dumps({"version": "5.1.0"}).encode())
        return _Resp(json.dumps(pypi).encode())

    monkeypatch.setattr(collector, "_open", fake_open)
    assert collector.resolve_release("npm:express") == collector.Release("npm:express@5.1.0")
    assert urls[-1] == "https://registry.npmjs.org/express/latest"
    release = collector.resolve_release("npm:@scope/pkg@next")
    assert release.source == "npm:@scope/pkg@5.1.0" and release.key == release.source
    assert urls[-1] == "https://registry.npmjs.org/@scope%2Fpkg/next"
    # PyPI: the version AND the file pip would install, since files can be added to a release.
    release = collector.resolve_release("pypi:requests")
    assert release.source == "pypi:requests==2.32.3"
    assert release.artifact == "requests-2.32.3-py3-none-any.whl"
    assert release.key.startswith("pypi:requests==2.32.3 requests-2.32.3-py3-none-any.whl ")
    # The whole file set is in the key: a file added to the release changes it.
    pypi["urls"].append(_dist("bdist_wheel", "requests-2.32.3-cp312-cp312-win_amd64.whl"))
    assert collector.resolve_release("pypi:requests").key != release.key
    assert urls[-1] == "https://pypi.org/pypi/requests/json"
    collector.resolve_release("pypi:requests==2.32.3")
    assert urls[-1] == "https://pypi.org/pypi/requests/2.32.3/json"
    # An exact npm pin needs no request; a git URL or a local path names no registry release.
    asked = len(urls)
    assert collector.resolve_release("npm:x@1.2.3") == collector.Release("npm:x@1.2.3")
    assert collector.resolve_release("https://github.com/o/r") is None
    assert collector.resolve_release("./local/dir") is None
    assert len(urls) == asked


def test_resolve_release_is_none_when_the_registry_cannot_say(monkeypatch):
    def offline(url, *, timeout):
        raise OSError("offline")

    monkeypatch.setattr(collector, "_open", offline)
    assert collector.resolve_release("npm:express") is None
    assert collector.resolve_release("pypi:requests") is None
    # A version that is not a plain version is not a key anyone should trust.
    monkeypatch.setattr(collector, "_open",
                        lambda url, *, timeout: _Resp(b'{"version": "1.0.0 and more"}'))
    assert collector.resolve_release("npm:express") is None
    # A release with no file to install has nothing to remember a verdict for.
    monkeypatch.setattr(collector, "_open",
                        lambda url, *, timeout: _Resp(b'{"info": {"version": "1.0"}, "urls": []}'))
    assert collector.resolve_release("pypi:x") is None


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


def _dist(kind, filename):
    return {"packagetype": kind, "filename": filename,
            "url": f"https://files.pythonhosted.org/packages/aa/{filename}"}


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        # pip installs the pure wheel on every platform; nothing in it runs at install time.
        ([_dist("sdist", "x-1.0.tar.gz"), _dist("bdist_wheel", "x-1.0-py3-none-any.whl")],
         "x-1.0-py3-none-any.whl"),
        # Only platform wheels: some machines build from the sdist and run its build script.
        ([_dist("bdist_wheel", "x-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"),
          _dist("sdist", "x-1.0.tar.gz")], "x-1.0.tar.gz"),
        ([_dist("bdist_wheel", "x-1.0-cp312-cp312-win_amd64.whl")],
         "x-1.0-cp312-cp312-win_amd64.whl"),
        # A pure wheel beside platform wheels is not what pip installs where a platform wheel
        # matches, so a clean one must not stand in for the release: the sdist is read instead.
        ([_dist("bdist_wheel", "x-1.0-py3-none-any.whl"),
          _dist("bdist_wheel", "x-1.0-cp312-cp312-win_amd64.whl"),
          _dist("sdist", "x-1.0.tar.gz")], "x-1.0.tar.gz"),
        ([], None),
    ],
)
def test_pypi_scans_the_file_pip_installs(files, expected):
    chosen = collector._pick_distribution(files)
    assert (chosen or {}).get("filename") == expected


def test_collect_pypi_wheel_is_named_by_the_registry(monkeypatch):
    # A wheel has no manifest at its root, and an sdist folder is `x-1.0`: the registry's project
    # name is the one the typosquatting check and the report header must see.
    meta = json.dumps(
        {
            "info": {"name": "Some-Pkg", "version": "1.0"},
            "urls": [_dist("sdist", "some_pkg-1.0.tar.gz"),
                     _dist("bdist_wheel", "some_pkg-1.0-py3-none-any.whl")],
        }
    ).encode()
    wheel = _zip({"some_pkg/__init__.py": "x = 1\n",
                  "some_pkg-1.0.dist-info/METADATA": "Name: Some-Pkg\nVersion: 1.0\n"})
    seen = []

    def fake_get(url):
        seen.append(url)
        return wheel if url.endswith(".whl") else meta

    monkeypatch.setattr(collector, "_http_get", fake_get)
    with collector.collect("pypi:some-pkg") as ctx:
        assert ctx.component.name == "Some-Pkg"
        assert ctx.component.version == "1.0"
        assert ctx.component.type == "python_package"
        assert (ctx.root / "some_pkg" / "__init__.py").exists()
    assert seen[-1].endswith("some_pkg-1.0-py3-none-any.whl")


def test_wheel_metadata_is_packaging_metadata_like_pkg_info():
    # A wheel's METADATA repeats the README as its long description, exactly like an sdist's
    # PKG-INFO: an example attack quoted in a README must not score from either.
    from skilltotal.file_index import is_doc_path

    assert is_doc_path("some_pkg-1.0.dist-info/METADATA")
    assert is_doc_path("PKG-INFO")
    assert not is_doc_path("some_pkg/__init__.py")


def test_collect_pypi_rejects_a_version_that_is_not_one(monkeypatch):
    monkeypatch.setattr(collector, "_http_get", lambda url: pytest.fail(f"fetched {url}"))
    with pytest.raises(CollectionError):
        with collector.collect("pypi:x==../../simple"):
            pass


def test_git_clone_timeout_becomes_collection_error(monkeypatch, tmp_path):
    """A hung/slow clone (subprocess timeout) surfaces as a clean CollectionError, not a hang."""
    import subprocess

    monkeypatch.setattr(collector, "_reject_if_too_large", lambda *_a, **_k: None)  # no network

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
