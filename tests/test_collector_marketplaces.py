"""Editor extensions by marketplace id or link: Visual Studio Marketplace (`vscode:`) and Open VSX
(`openvsx:`). Offline: every HTTP exchange goes to a stand-in transport."""

from __future__ import annotations

import gzip
import io
import json
import urllib.error
import zipfile

import pytest

from skilltotal import collector, engine
from skilltotal.collector import CollectionError, SizeLimitError

_VSM_QUERY = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
_VSM_PACKAGE = ("https://marketplace.visualstudio.com/_apis/public/gallery/publishers/acme/"
                "vsextensions/tiny/{version}/vspackage")
_OVSX_API = "https://open-vsx.org/api/acme/tiny"
_OVSX_QUERY = "https://open-vsx.org/vscode/gallery/extensionquery"


def _vsix(version: str = "1.2.3") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("extension.vsixmanifest", "<PackageManifest/>")
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("extension/package.json", json.dumps({
            "name": "tiny", "publisher": "acme", "version": version,
            "engines": {"vscode": "^1.80.0"}, "main": "./extension.js"}))
        zf.writestr("extension/extension.js", "exports.activate = () => {};\n")
    return buf.getvalue()


class _Resp:
    def __init__(self, body: bytes = b"", status: int = 200, headers: dict | None = None):
        self.body = body
        self._buf = io.BytesIO(body)
        self.status = status
        self.headers = headers or {}

    def read(self, n: int = -1) -> bytes:
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _not_found(url: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO(b"{}"))


class _Transport:
    """Answers each request from ``routes`` (method, url) -> response or exception; records them."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.requests: list[tuple[str, str, bytes | None]] = []

    def __call__(self, request, timeout):
        key = (request.get_method(), request.full_url)
        self.requests.append((*key, request.data))
        answer = self.routes.get(key)
        if answer is None:
            raise _not_found(request.full_url)
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return answer()
        return _Resp(answer.body, answer.status, answer.headers)  # a fresh one for each request

    def urls(self) -> list[str]:
        return [url for _, url, _ in self.requests]


@pytest.fixture
def transport(monkeypatch):
    def install(routes: dict) -> _Transport:
        t = _Transport(routes)
        monkeypatch.setattr(collector, "_marketplace_send", t)
        return t
    return install


def _gallery(*builds: tuple[str, str | None, bool], publisher="acme", name="tiny") -> bytes:
    versions = []
    for version, platform, prerelease in builds:
        entry = {"version": version, "properties": [
            {"key": "Microsoft.VisualStudio.Code.Engine", "value": "^1.80.0"}]}
        if platform:
            entry["targetPlatform"] = platform
        if prerelease:
            entry["properties"].append(
                {"key": "Microsoft.VisualStudio.Code.PreRelease", "value": "true"})
        versions.append(entry)
    ext = {"publisher": {"publisherName": publisher}, "extensionName": name, "versions": versions}
    return json.dumps({"results": [{"extensions": [ext]}]}).encode()


def _ovsx_doc(version: str, platforms=("universal",), *, prerelease=False, sizes=None,
              host="https://open-vsx.org") -> bytes:
    downloads = {p: f"{host}/api/acme/tiny/{p}/{version}/file/acme.tiny-{version}@{p}.vsix"
                 for p in platforms}
    return json.dumps({
        "namespace": "acme", "name": "tiny", "version": version, "preRelease": prerelease,
        "targetPlatform": platforms[0], "downloads": downloads,
        "downloadSizes": sizes or {p: 1000 for p in platforms},
        "files": {"download": downloads[platforms[0]]}}).encode()


def _ovsx_file(version: str, platform: str = "universal") -> str:
    return f"https://open-vsx.org/api/acme/tiny/{platform}/{version}/file/acme.tiny-{version}@{platform}.vsix"


# ------------------------------------------------------------------ parsing


def test_classify_source_recognizes_both_prefixes_and_links():
    assert collector.classify_source("vscode:acme.tiny") == "vscode"
    assert collector.classify_source("VSCode:acme.tiny@1.0.0") == "vscode"
    assert collector.classify_source("openvsx:acme.tiny") == "openvsx"
    assert collector.classify_source(
        "https://marketplace.visualstudio.com/items?itemName=acme.tiny") == "vscode"
    assert collector.classify_source("https://open-vsx.org/extension/acme/tiny") == "openvsx"
    # A marketplace link with a bad id is still an extension source, refused as an input error,
    # never handed to git as a repository URL.
    assert collector.classify_source(
        "https://marketplace.visualstudio.com/items?itemName=$(id)") == "vscode"
    assert collector.classify_source("https://marketplace.visualstudio.com/search?q=x") == "git"
    assert collector.classify_source("https://github.com/acme/tiny") == "git"


@pytest.mark.parametrize(("source", "expected"), [
    ("vscode:ms-python.python", ("ms-python.python", None)),
    ("vscode:Anthropic.claude-code@2.1.314", ("Anthropic.claude-code", "2.1.314")),
    ("vscode:acme.tiny@latest", ("acme.tiny", None)),
    ("openvsx:acme.tiny@1.0.0-beta+2", ("acme.tiny", "1.0.0-beta+2")),
    ("  openvsx:acme.tiny  ", ("acme.tiny", None)),
    ("https://marketplace.visualstudio.com/items?itemName=acme.tiny", ("acme.tiny", None)),
    ("https://marketplace.visualstudio.com/items?itemName=acme.tiny&ssr=false#overview",
     ("acme.tiny", None)),
    ("https://open-vsx.org/extension/acme/tiny", ("acme.tiny", None)),
    ("https://open-vsx.org/extension/acme/tiny/", ("acme.tiny", None)),
    ("https://open-vsx.org/extension/acme/tiny/2.1.313", ("acme.tiny", "2.1.313")),
    ("https://open-vsx.org/extension/acme/tiny?tab=changes", ("acme.tiny", None)),
])
def test_extension_spec_parses_valid_sources(source, expected):
    assert collector.extension_spec(source) == expected


@pytest.mark.parametrize("source", [
    "vscode:", "vscode:tiny", "vscode:.tiny", "vscode:acme.", "vscode:acme.tiny.extra",
    "vscode:../evil", "vscode:acme.tiny/../../x", "vscode:acme.tiny@../../x", "vscode:acme.tiny@..",
    "vscode:acme.tiny@.1", "vscode:acme.tiny@", "vscode:acme.tiny@1.0;rm -rf",
    "vscode:acme.tiny@1 0",
    "vscode:acme.tiny\nx", "vscode:acme.tiny@1.0.0\nx", "vscode:acme.ti_ny", "vscode:-acme.tiny",
    "vscode:acme.tiny?x=1", "vscode:acme.tiny#x", "vscode:acme.tiny@1.0@2.0",
    "vscode:Kelvin.tiny",  # the Kelvin sign case-folds to k under re.IGNORECASE
    "vscode:acme.tıny",  # dotless i
    "vscode:" + "a" * 129 + ".tiny", "vscode:acme.tiny@" + "1" * 65,
    "https://marketplace.visualstudio.com/items?itemName=$(id)",
    "https://marketplace.visualstudio.com/items?itemName=acme.tiny%2F..%2F..",
    "https://marketplace.visualstudio.com/items?itemName=acme.tiny/../../x",
    "https://marketplace.visualstudio.com/items?itemName=acme.tiny&itemName=evil.other",
    "https://marketplace.visualstudio.com/items?itemName=acme.tiny%0aX",
    "https://marketplace.visualstudio.com/items?itemName=",
    "https://marketplace.visualstudio.com/items?other=acme.tiny",
    "https://open-vsx.org/extension/acme",
    "https://open-vsx.org/extension/acme/tiny/1.0.0/extra",
    "https://open-vsx.org/extension/%2e%2e/tiny",
    "https://open-vsx.org/extension/acme/tiny/%2e%2e",
    "https://open-vsx.org/extension/acme/tiny/..",
    "npm:acme.tiny", "https://github.com/acme/tiny",
])
def test_extension_spec_rejects_invalid_and_injection_shaped_input(source):
    assert collector.extension_spec(source) == (None, None)


@pytest.mark.parametrize("source", [
    "vscode:../evil", "openvsx:acme.tiny@..",
    "https://marketplace.visualstudio.com/items?itemName=$(id)",
])
def test_invalid_extension_is_an_input_error_without_any_request(transport, source):
    t = transport({})
    with pytest.raises(CollectionError, match="invalid .* extension"):
        collector.collect(source)
    assert t.requests == []


# ------------------------------------------------------------------ Visual Studio Marketplace


def test_vscode_resolves_latest_stable_and_scans_the_universal_build(transport):
    vsix = gzip.compress(_vsix("2.0.0"))
    t = transport({
        ("POST", _VSM_QUERY): _Resp(_gallery(("2.1.0", None, True), ("2.0.0", None, False))),
        ("GET", _VSM_PACKAGE.format(version="2.0.0")):
            lambda: _Resp(vsix, headers={"Content-Encoding": "gzip"}),
    })
    with collector.collect("vscode:acme.tiny") as ctx:
        assert ctx.component.type == "vscode_extension"
        assert (ctx.component.name, ctx.component.version) == ("tiny", "2.0.0")
        assert ctx.component.source == "vscode:acme.tiny"
        assert ctx.component.download_url == _VSM_PACKAGE.format(version="2.0.0")
        assert ctx.distribution_note is None  # one universal build: nothing left unread
    query = json.loads(t.requests[0][2])
    assert query["filters"][0]["criteria"][0] == {"filterType": 7, "value": "acme.tiny"}
    assert query["flags"] & 0x10000  # unpinned: latest stable and pre-release only


def test_vscode_platform_build_choice_is_linux_x64_and_the_report_says_so(transport):
    builds = [("3.0.0", p, False) for p in ("darwin-arm64", "win32-x64", "linux-x64")]
    t = transport({
        ("POST", _VSM_QUERY): _Resp(_gallery(*builds, ("2.0.0", None, False))),
        ("GET", _VSM_PACKAGE.format(version="3.0.0") + "?targetPlatform=linux-x64"):
            lambda: _Resp(gzip.compress(_vsix("3.0.0")), headers={"Content-Encoding": "gzip"}),
    })
    with collector.collect("vscode:acme.tiny") as ctx:
        assert ctx.component.version == "3.0.0"  # newest version, not the older universal one
        assert "linux-x64" in ctx.component.download_url
        assert ctx.distribution_note == (
            "Scanned the linux-x64 build of acme.tiny 3.0.0; the builds for darwin-arm64, "
            "win32-x64 were not read (a platform build can carry different code, such as native "
            "binaries).")
    assert t.urls()[-1].endswith("?targetPlatform=linux-x64")


@pytest.mark.parametrize(("platforms", "expected"), [
    (["win32-x64", "universal", "linux-x64"], "universal"),
    (["win32-x64", "linux-x64"], "linux-x64"),
    (["win32-x64", "darwin-arm64"], "darwin-arm64"),
])
def test_platform_preference(platforms, expected):
    assert collector._pick_platform(platforms) == expected


def test_vscode_pinned_version_and_missing_version(transport):
    t = transport({
        ("POST", _VSM_QUERY): _Resp(_gallery(("2.0.0", None, False), ("1.0.0", None, False))),
        ("GET", _VSM_PACKAGE.format(version="1.0.0")): lambda: _Resp(_vsix("1.0.0")),
    })
    with collector.collect("vscode:acme.tiny@1.0.0") as ctx:
        assert ctx.component.version == "1.0.0"
    assert not json.loads(t.requests[-2][2])["flags"] & 0x10000  # a pin reads every version
    with pytest.raises(CollectionError, match="has no version '9.9.9'") as exc:
        collector.collect("vscode:acme.tiny@9.9.9")
    assert collector.failure_category(exc.value) == "not-found"


def test_vscode_unknown_extension_is_not_found(transport):
    empty = json.dumps({"results": [{"extensions": []}]}).encode()
    transport({("POST", _VSM_QUERY): _Resp(empty)})
    with pytest.raises(CollectionError, match="not found on the Visual Studio Marketplace") as e:
        collector.collect("vscode:acme.tiny")
    assert collector.failure_category(e.value) == "not-found"


def test_vscode_only_prereleases_published_scans_the_newest_and_says_so(transport):
    transport({
        ("POST", _VSM_QUERY): _Resp(_gallery(("0.2.0", None, True), ("0.1.0", None, True))),
        ("GET", _VSM_PACKAGE.format(version="0.2.0")): lambda: _Resp(_vsix("0.2.0")),
    })
    with collector.collect("vscode:acme.tiny") as ctx:
        assert ctx.component.version == "0.2.0"
        assert "no stable release" in ctx.distribution_note


def test_vscode_follows_a_redirect_to_its_cdn_only(transport):
    cdn = "https://acme.gallerycdn.vsassets.io/extensions/acme/tiny/1.0.0/x/VSIXPackage"
    query = _Resp(_gallery(("1.0.0", None, False)))
    package = _VSM_PACKAGE.format(version="1.0.0")
    transport({("POST", _VSM_QUERY): query,
               ("GET", package): _Resp(status=302, headers={"Location": cdn}),
               ("GET", cdn): lambda: _Resp(_vsix("1.0.0"))})
    with collector.collect("vscode:acme.tiny") as ctx:
        assert ctx.component.version == "1.0.0"

    for target in ("https://evil.example/x.vsix", "http://acme.gallerycdn.vsassets.io/x",
                   "https://acme.gallerycdn.vsassets.io.evil.example/x",
                   "https://user@acme.gallerycdn.vsassets.io/x",
                   "https://acme.gallerycdn.vsassets.io:8443/x"):
        t = transport({("POST", _VSM_QUERY): _Resp(_gallery(("1.0.0", None, False))),
                       ("GET", package): _Resp(status=302, headers={"Location": target})})
        with pytest.raises(CollectionError, match="refusing to fetch from"):
            collector.collect("vscode:acme.tiny")
        assert target not in t.urls()


def test_a_redirected_gallery_query_is_refused(transport):
    transport({("POST", _VSM_QUERY): _Resp(status=307, headers={
        "Location": "https://marketplace.visualstudio.com/other"})})
    with pytest.raises(CollectionError, match="query was redirected"):
        collector.collect("vscode:acme.tiny")


def test_redirect_loops_stop(transport):
    package = _VSM_PACKAGE.format(version="1.0.0")
    transport({("POST", _VSM_QUERY): _Resp(_gallery(("1.0.0", None, False))),
               ("GET", package): lambda: _Resp(status=302, headers={"Location": package})})
    with pytest.raises(CollectionError, match="too many redirects"):
        collector.collect("vscode:acme.tiny")


# ------------------------------------------------------------------ size and encoding


def test_download_over_the_archive_limit_is_refused(transport, monkeypatch):
    monkeypatch.setattr(collector, "_MAX_ARCHIVE_BYTES", 4096)
    package = _VSM_PACKAGE.format(version="1.0.0")
    query = _gallery(("1.0.0", None, False))
    # Plain body over the cap, and a small gzip body that inflates past it.
    for body, headers in ((b"PK\x03\x04" + b"x" * 8192, {}),
                          (gzip.compress(b"PK\x03\x04" + b"\0" * 10_000_000),
                           {"Content-Encoding": "gzip"})):
        assert len(body) > 4096 or headers
        transport({("POST", _VSM_QUERY): _Resp(query),
                   ("GET", package): lambda b=body, h=headers: _Resp(b, headers=h)})
        with pytest.raises(SizeLimitError, match="exceeds the size limit of 0 MB") as exc:
            collector.collect("vscode:acme.tiny")
        assert exc.value.variable == "SKILLTOTAL_MAX_ARCHIVE_MB"


def test_damaged_or_truncated_gzip_and_non_vsix_bodies_are_errors(transport):
    package = _VSM_PACKAGE.format(version="1.0.0")
    query = _gallery(("1.0.0", None, False))
    whole = gzip.compress(_vsix("1.0.0"))
    for body, headers, message in (
            (b"not gzip at all", {"Content-Encoding": "gzip"}, "gzip encoding is damaged"),
            (whole[: len(whole) // 2], {"Content-Encoding": "gzip"}, "ended early"),
            (b"<html>blocked</html>", {}, "did not return a .vsix package")):
        transport({("POST", _VSM_QUERY): _Resp(query),
                   ("GET", package): lambda b=body, h=headers: _Resp(b, headers=h)})
        with pytest.raises(CollectionError, match=message):
            collector.collect("vscode:acme.tiny")


def test_gzip_encoded_gallery_answer_is_decoded(transport):
    transport({
        ("POST", _VSM_QUERY): _Resp(gzip.compress(_gallery(("1.0.0", None, False))),
                                    headers={"Content-Encoding": "gzip"}),
        ("GET", _VSM_PACKAGE.format(version="1.0.0")): lambda: _Resp(_vsix("1.0.0")),
    })
    with collector.collect("vscode:acme.tiny") as ctx:
        assert ctx.component.version == "1.0.0"


# ------------------------------------------------------------------ Open VSX


def test_openvsx_scans_the_linux_x64_build_named_by_its_api(transport):
    platforms = ("alpine-arm64", "linux-x64", "win32-x64")
    t = transport({
        ("GET", _OVSX_API): _Resp(_ovsx_doc("2.1.316", platforms)),
        ("GET", _ovsx_file("2.1.316", "linux-x64")): lambda: _Resp(_vsix("2.1.316")),
    })
    with collector.collect("openvsx:acme.tiny") as ctx:
        assert ctx.component.type == "vscode_extension"
        assert ctx.component.version == "2.1.316"
        assert ctx.component.download_url == _ovsx_file("2.1.316", "linux-x64")
        assert "alpine-arm64, win32-x64 were not read" in ctx.distribution_note
    assert t.urls() == [_OVSX_API, _ovsx_file("2.1.316", "linux-x64")]


def test_openvsx_link_with_a_version(transport):
    transport({
        ("GET", f"{_OVSX_API}/2.1.313"): _Resp(_ovsx_doc("2.1.313")),
        ("GET", _ovsx_file("2.1.313")): lambda: _Resp(_vsix("2.1.313")),
    })
    with collector.collect("https://open-vsx.org/extension/acme/tiny/2.1.313") as ctx:
        assert ctx.component.version == "2.1.313"
        assert ctx.distribution_note is None


def test_openvsx_missing_extension_or_version_is_not_found(transport):
    transport({})
    for source, message in (("openvsx:acme.tiny", "extension 'acme.tiny' was not found"),
                            ("openvsx:acme.tiny@2.1.313",
                             "extension 'acme.tiny' 2.1.313 was not found on Open VSX")):
        with pytest.raises(CollectionError, match=message) as exc:
            collector.collect(source)
        assert collector.failure_category(exc.value) == "not-found"


def test_openvsx_prerelease_latest_resolves_to_the_newest_stable(transport):
    t = transport({
        ("GET", _OVSX_API): _Resp(_ovsx_doc("2.1.0", prerelease=True)),
        ("POST", _OVSX_QUERY): _Resp(_gallery(("2.1.0", "universal", True),
                                              ("2.0.0", "universal", False),
                                              ("1.9.0", "universal", False))),
        ("GET", f"{_OVSX_API}/2.0.0"): _Resp(_ovsx_doc("2.0.0")),
        ("GET", _ovsx_file("2.0.0")): lambda: _Resp(_vsix("2.0.0")),
    })
    with collector.collect("openvsx:acme.tiny") as ctx:
        assert ctx.component.version == "2.0.0"
    assert f"{_OVSX_API}/2.0.0" in t.urls()


def test_openvsx_stated_size_over_the_limit_refuses_before_downloading(transport, monkeypatch):
    monkeypatch.setattr(collector, "_MAX_ARCHIVE_BYTES", 150 * 1024 * 1024)
    t = transport({("GET", _OVSX_API): _Resp(_ovsx_doc(
        "2.1.316", ("linux-x64",), sizes={"linux-x64": 160_417_327}))})
    with pytest.raises(SizeLimitError, match=r"\(152 MB\) exceeds the size limit of 150 MB"):
        collector.collect("openvsx:acme.tiny")
    assert t.urls() == [_OVSX_API]


def test_openvsx_download_off_its_hosts_is_refused(transport):
    # The API's own download URL on another host, and a redirect from the file URL to one.
    transport({("GET", _OVSX_API): _Resp(_ovsx_doc("1.0.0", host="https://evil.example"))})
    with pytest.raises(CollectionError, match="refusing to fetch from evil.example"):
        collector.collect("openvsx:acme.tiny")

    cdn = "https://openvsx.eclipsecontent.org/acme/tiny/universal/1.0.0/acme.tiny-1.0.0.vsix"
    transport({("GET", _OVSX_API): _Resp(_ovsx_doc("1.0.0")),
               ("GET", _ovsx_file("1.0.0")): _Resp(status=302, headers={"Location": cdn}),
               ("GET", cdn): lambda: _Resp(_vsix("1.0.0"))})
    with collector.collect("openvsx:acme.tiny") as ctx:
        assert ctx.component.version == "1.0.0"

    t = transport({("GET", _OVSX_API): _Resp(_ovsx_doc("1.0.0")),
                   ("GET", _ovsx_file("1.0.0")): _Resp(
                       status=302, headers={"Location": "https://evil.example/x.vsix"})})
    with pytest.raises(CollectionError, match="refusing to fetch from evil.example"):
        collector.collect("openvsx:acme.tiny")
    assert "https://evil.example/x.vsix" not in t.urls()


def test_network_failures_keep_the_fetch_categories(transport):
    transport({("GET", _OVSX_API): urllib.error.URLError("[Errno 11001] getaddrinfo failed")})
    with pytest.raises(CollectionError) as exc:
        collector.collect("openvsx:acme.tiny")
    assert collector.failure_category(exc.value) == "offline"


def test_resolve_release_names_the_version_a_scan_would_read(transport):
    t = transport({
        ("POST", _VSM_QUERY): _Resp(_gallery(("2.1.0", None, True), ("2.0.0", "linux-x64", False))),
        ("GET", _OVSX_API): _Resp(_ovsx_doc("3.0.0")),
    })
    assert collector.resolve_release("vscode:acme.tiny") == collector.Release(
        "vscode:acme.tiny@2.0.0")
    assert collector.resolve_release(
        "https://open-vsx.org/extension/acme/tiny").source == "openvsx:acme.tiny@3.0.0"
    count = len(t.requests)
    # A pin needs no request; an invalid id or an unknown extension resolves to nothing.
    assert collector.resolve_release("openvsx:acme.tiny@1.0.0").source == "openvsx:acme.tiny@1.0.0"
    assert len(t.requests) == count
    assert collector.resolve_release("vscode:../evil") is None
    transport({})
    assert collector.resolve_release("openvsx:acme.tiny") is None


# ------------------------------------------------------------------ end to end


@pytest.mark.parametrize("source", ["openvsx:acme.tiny@1.2.3",
                                    "https://marketplace.visualstudio.com/items?itemName=acme.tiny"])
def test_analyze_end_to_end_reports_a_vscode_extension(transport, source):
    transport({
        ("GET", f"{_OVSX_API}/1.2.3"): _Resp(_ovsx_doc("1.2.3", ("linux-x64", "darwin-arm64"))),
        ("GET", _ovsx_file("1.2.3", "linux-x64")): lambda: _Resp(_vsix()),
        ("POST", _VSM_QUERY): _Resp(_gallery(("1.2.3", None, False))),
        ("GET", _VSM_PACKAGE.format(version="1.2.3")):
            lambda: _Resp(gzip.compress(_vsix()), headers={"Content-Encoding": "gzip"}),
    })
    report = engine.analyze(source).to_dict()
    component = report["component"]
    assert (component["type"], component["name"], component["version"]) == (
        "vscode_extension", "tiny", "1.2.3")
    assert component["source"] == source
    notes = [n["reason"] for n in report["needs_review"] if n.get("category") == "coverage"]
    if source.startswith("openvsx:"):
        assert any("linux-x64 build" in n and "darwin-arm64" in n for n in notes)
    else:
        assert not any("build of" in n for n in notes)
