"""Scanning through a company registry mirror (SKILLTOTAL_NPM_REGISTRY, SKILLTOTAL_PYPI_INDEX).

The mirror is read only from the scanning process's environment. The token
(SKILLTOTAL_REGISTRY_TOKEN) goes to the mirror's own scheme and host and nowhere else: not to the
public registries, not to a download host the mirror redirects to. The hook checks a package
through the mirror only when the installer's own registry is that mirror; any other custom
registry stays unchecked.

Nothing here reaches the network: the registries are faked, and the one HTTP server is on
127.0.0.1 inside this process. Hosts are reserved `.invalid` / `.example` names.
"""

from __future__ import annotations

import http.server
import io
import json
import tarfile
import threading
import urllib.request
import zipfile

import pytest

from skilltotal import cli, collector, hook_scan, provenance
from skilltotal.agent_hook import hook_response
from skilltotal.collector import (
    NPM_REGISTRY_ENV,
    PYPI_INDEX_ENV,
    REGISTRY_TOKEN_ENV,
    CollectionError,
    normalize_registry_url,
)

NPM_MIRROR = "https://npm.corp.example/artifactory/api/npm/npm-remote"
PYPI_MIRROR = "https://pypi.corp.example/artifactory/api/pypi/pypi-remote"
OTHER = "https://other.registry.invalid"
TOKEN = "t0ken-for-the-mirror-only"


def _tgz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _wheel() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("x/__init__.py", "VALUE = 1\n")
    return buf.getvalue()


# --- the setting ---------------------------------------------------------------------------------

@pytest.mark.parametrize(("value", "expected"), [
    ("https://npm.corp.example/api/npm/remote/", "https://npm.corp.example/api/npm/remote"),
    ("  HTTPS://NPM.Corp.Example:8443/x//  ", "https://npm.corp.example:8443/x"),
    ("https://npm.corp.example", "https://npm.corp.example"),
    ("http://localhost:4873/", "http://localhost:4873"),
    ("http://127.0.0.1:3141/root/pypi", "http://127.0.0.1:3141/root/pypi"),
    ("http://[::1]:4873", "http://[::1]:4873"),
])
def test_a_mirror_url_is_normalized(value, expected):
    assert normalize_registry_url(value, NPM_REGISTRY_ENV) == expected


@pytest.mark.parametrize(("value", "why"), [
    ("http://npm.corp.example", "plain http"),
    ("https://user:s3cret-pass@npm.corp.example", "user name or password"),
    ("https://s3cret-pass@npm.corp.example", "user name or password"),
    ("https://npm.corp.example/?token=s3cret-pass", "query"),
    ("https://npm.corp.example/#s3cret-pass", "fragment"),
    ("ftp://npm.corp.example", "https://"),
    ("file:///etc/passwd", "https://"),
    ("npm.corp.example", "https://"),
    ("https://", "no host"),
    ("https://npm.corp.example:99999", "port"),
    ("https://npm.corp.example/a/../b", ". or .."),
    ("https://npm.corp.example/a b", "characters"),
    ("https://npm.corp.example\\x", "characters"),
])
def test_an_unusable_mirror_url_is_refused_by_name_without_quoting_it(value, why):
    with pytest.raises(CollectionError) as caught:
        normalize_registry_url(value, PYPI_INDEX_ENV)
    message = str(caught.value)
    assert message.startswith(f"{PYPI_INDEX_ENV} is not a usable registry URL")
    assert why in message
    assert "s3cret" not in message


def test_an_unusable_setting_stops_a_registry_scan_with_its_name(monkeypatch):
    monkeypatch.setenv(NPM_REGISTRY_ENV, "http://npm.corp.example")
    monkeypatch.setattr(collector, "_http_get", lambda url: pytest.fail(f"fetched {url}"))
    with pytest.raises(CollectionError, match=NPM_REGISTRY_ENV):
        collector.collect("npm:x")
    assert collector.resolve_release("npm:x") is None  # a lookup says it does not know


# --- npm through the mirror ----------------------------------------------------------------------

def _npm_mirror(monkeypatch, tarball_url: str, *, per_version: bool = True) -> list[str]:
    asked: list[str] = []
    tarball = _tgz({"package/package.json": b'{"name":"x","version":"1.2.3"}',
                    "package/index.js": b"module.exports = 1;\n"})

    def fake_get(url):
        asked.append(url)
        if url.endswith(".tgz"):
            return tarball
        if url.endswith("/x/latest"):
            if not per_version:
                raise CollectionError("failed to fetch") from urllib.error.HTTPError(
                    url, 404, "Not Found", {}, None)
            return json.dumps({"version": "1.2.3", "dist": {"tarball": tarball_url}}).encode()
        return json.dumps({"dist-tags": {"latest": "1.2.3"},
                           "versions": {"1.2.3": {"dist": {"tarball": tarball_url}}}}).encode()

    monkeypatch.setattr(collector, "_http_get", fake_get)
    return asked


def test_without_a_mirror_the_public_registry_is_read(monkeypatch):
    asked = _npm_mirror(monkeypatch, "https://registry.npmjs.org/x/-/x-1.2.3.tgz")
    with collector.collect("npm:x") as ctx:
        assert ctx.mirror_note is None
    assert asked == ["https://registry.npmjs.org/x/latest",
                     "https://registry.npmjs.org/x/-/x-1.2.3.tgz"]


@pytest.mark.parametrize("per_version", [True, False])
def test_an_npm_package_is_fetched_from_the_mirror(monkeypatch, per_version):
    monkeypatch.setenv(NPM_REGISTRY_ENV, NPM_MIRROR + "/")
    tarball = f"{NPM_MIRROR}/x/-/x-1.2.3.tgz"
    asked = _npm_mirror(monkeypatch, tarball, per_version=per_version)
    with collector.collect("npm:x") as ctx:
        assert ctx.component.download_url == tarball
        assert "registry mirror at https://npm.corp.example" in ctx.mirror_note
        assert NPM_REGISTRY_ENV in ctx.mirror_note
    assert all(url.startswith(NPM_MIRROR + "/") for url in asked), asked


def test_a_relative_tarball_url_is_read_against_the_mirror(monkeypatch):
    monkeypatch.setenv(NPM_REGISTRY_ENV, NPM_MIRROR)
    _npm_mirror(monkeypatch, "/artifactory/api/npm/npm-remote/x/-/x-1.2.3.tgz")
    with collector.collect("npm:x") as ctx:
        assert ctx.component.download_url == f"{NPM_MIRROR}/x/-/x-1.2.3.tgz"


def test_the_mirror_may_hand_out_the_public_registrys_tarball(monkeypatch):
    monkeypatch.setenv(NPM_REGISTRY_ENV, NPM_MIRROR)
    _npm_mirror(monkeypatch, "https://registry.npmjs.org/x/-/x-1.2.3.tgz")
    with collector.collect("npm:x") as ctx:
        assert ctx.component.download_url.startswith("https://registry.npmjs.org/")


@pytest.mark.parametrize("tarball", [
    "https://elsewhere.invalid/x-1.2.3.tgz",
    "http://registry.npmjs.org/x/-/x-1.2.3.tgz",
    "http://npm.corp.example/artifactory/api/npm/npm-remote/x/-/x-1.2.3.tgz",
    "https://files.pythonhosted.org/x-1.2.3.tgz",
])
def test_a_tarball_off_the_mirror_and_the_public_registry_is_refused(monkeypatch, tarball):
    monkeypatch.setenv(NPM_REGISTRY_ENV, NPM_MIRROR)
    asked = _npm_mirror(monkeypatch, tarball)
    with pytest.raises(CollectionError, match="neither the mirror nor the public registry"):
        collector.collect("npm:x")
    assert not any(url.endswith(".tgz") for url in asked)


def test_resolve_release_asks_the_mirror_unless_told_not_to(monkeypatch):
    monkeypatch.setenv(NPM_REGISTRY_ENV, NPM_MIRROR)
    urls = []

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_open(url, *, timeout):
        urls.append(url)
        return _Resp(b'{"version": "5.1.0"}')

    monkeypatch.setattr(collector, "_open", fake_open)
    assert collector.resolve_release("npm:express").source == "npm:express@5.1.0"
    assert urls[-1] == f"{NPM_MIRROR}/express/latest"
    collector.resolve_release("npm:express", use_mirror=False)
    assert urls[-1] == "https://registry.npmjs.org/express/latest"


# --- PyPI through the mirror ---------------------------------------------------------------------

def _pypi_mirror(monkeypatch, file_url: str) -> list[str]:
    asked: list[str] = []
    meta = {"info": {"name": "x", "version": "1.0"},
            "urls": [{"packagetype": "bdist_wheel", "filename": "x-1.0-py3-none-any.whl",
                      "url": file_url}]}

    def fake_get(url):
        asked.append(url)
        return _wheel() if url.endswith(".whl") else json.dumps(meta).encode()

    monkeypatch.setattr(collector, "_http_get", fake_get)
    return asked


def test_a_pypi_package_is_fetched_from_the_mirror(monkeypatch):
    monkeypatch.setenv(PYPI_INDEX_ENV, PYPI_MIRROR)
    wheel = f"{PYPI_MIRROR}/packages/x-1.0-py3-none-any.whl"
    asked = _pypi_mirror(monkeypatch, wheel)
    with collector.collect("pypi:x==1.0") as ctx:
        assert ctx.component.download_url == wheel
        assert PYPI_INDEX_ENV in ctx.mirror_note
    assert asked == [f"{PYPI_MIRROR}/pypi/x/1.0/json", wheel]


def test_the_pypi_mirror_may_hand_out_pythonhosted_files(monkeypatch):
    monkeypatch.setenv(PYPI_INDEX_ENV, PYPI_MIRROR)
    _pypi_mirror(monkeypatch, "https://files.pythonhosted.org/packages/x-1.0-py3-none-any.whl")
    with collector.collect("pypi:x") as ctx:
        assert ctx.component.download_url.startswith("https://files.pythonhosted.org/")


def test_a_pypi_file_on_another_host_is_refused(monkeypatch):
    monkeypatch.setenv(PYPI_INDEX_ENV, PYPI_MIRROR)
    _pypi_mirror(monkeypatch, "https://elsewhere.invalid/x-1.0-py3-none-any.whl")
    with pytest.raises(CollectionError, match="points the download at elsewhere.invalid"):
        collector.collect("pypi:x")


def test_the_npm_mirror_does_not_change_pypi(monkeypatch):
    monkeypatch.setenv(NPM_REGISTRY_ENV, NPM_MIRROR)
    asked = _pypi_mirror(monkeypatch, "https://files.pythonhosted.org/x-1.0-py3-none-any.whl")
    with collector.collect("pypi:x") as ctx:
        assert ctx.mirror_note is None
    assert asked[0] == "https://pypi.org/pypi/x/json"


def test_provenance_reads_the_mirror(monkeypatch):
    """Asking the public registry about a package fetched from the mirror would tell it the
    names of the company's internal packages."""
    monkeypatch.setenv(NPM_REGISTRY_ENV, NPM_MIRROR)
    monkeypatch.setenv(PYPI_INDEX_ENV, PYPI_MIRROR)
    urls = []
    monkeypatch.setattr(provenance, "_fetch", lambda url: urls.append(url) or {})
    provenance.collect_provenance("npm:@corp/x")
    provenance.collect_provenance("pypi:x")
    assert urls == [f"{NPM_MIRROR}/@corp%2Fx", f"{PYPI_MIRROR}/pypi/x/json"]


# --- the token -----------------------------------------------------------------------------------

class _Recorder(http.server.BaseHTTPRequestHandler):
    seen: list[tuple[str, str | None]] = []

    def do_GET(self):  # noqa: N802 - the http.server name
        _Recorder.seen.append((self.path, self.headers.get("Authorization")))
        if self.path == "/mirror/same":
            self.send_response(302)
            self.send_header("Location", "/mirror/doc")
        elif self.path == "/mirror/away":
            port = self.server.server_address[1]
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{port}/mirror/doc")
        elif self.path == "/mirror/missing":
            self.send_response(404)
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")
            return
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def local_mirror(monkeypatch):
    _Recorder.seen = []
    server = http.server.HTTPServer(("127.0.0.1", 0), _Recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy",
                 "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv(PYPI_INDEX_ENV, f"{base}/mirror")
    monkeypatch.setenv(REGISTRY_TOKEN_ENV, TOKEN)
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()


def test_the_token_goes_to_the_mirror_and_follows_a_redirect_on_it(local_mirror):
    assert collector._http_get(f"{local_mirror}/mirror/same") == b"{}"
    assert _Recorder.seen == [("/mirror/same", f"Bearer {TOKEN}"),
                              ("/mirror/doc", f"Bearer {TOKEN}")]


def test_a_redirect_off_the_mirror_over_http_is_refused(local_mirror):
    with pytest.raises(CollectionError, match="redirect to a non-https URL"):
        collector._http_get(f"{local_mirror}/mirror/away")
    assert [path for path, _ in _Recorder.seen] == ["/mirror/away"]


def test_a_failed_request_never_quotes_the_token(local_mirror):
    with pytest.raises(CollectionError) as caught:
        collector._http_get(f"{local_mirror}/mirror/missing")
    assert TOKEN not in str(caught.value) and TOKEN not in repr(caught.value.__cause__)


def _redirect(origins, newurl):
    handler = collector._MirrorRedirects(origins)
    request = urllib.request.Request(f"{PYPI_MIRROR}/pypi/x/json")
    request.add_unredirected_header("Authorization", f"Bearer {TOKEN}")
    return handler.redirect_request(request, io.BytesIO(), 302, "Found", {}, newurl)


def test_a_cross_host_redirect_does_not_carry_the_token(monkeypatch):
    monkeypatch.setenv(PYPI_INDEX_ENV, PYPI_MIRROR)
    monkeypatch.setenv(REGISTRY_TOKEN_ENV, TOKEN)
    origins = collector._mirror_origins()
    away = _redirect(origins, "https://storage.example/bucket/x.whl?sig=1")
    assert away.full_url.startswith("https://storage.example/")
    assert not away.has_header("Authorization")
    assert "Authorization" not in away.unredirected_hdrs
    same = _redirect(origins, f"{PYPI_MIRROR}/files/x.whl")
    assert same.unredirected_hdrs["Authorization"] == f"Bearer {TOKEN}"
    with pytest.raises(CollectionError):
        _redirect(origins, "http://storage.example/x.whl")


def test_the_token_is_never_sent_to_a_public_registry(monkeypatch):
    monkeypatch.setenv(REGISTRY_TOKEN_ENV, TOKEN)
    monkeypatch.setenv(NPM_REGISTRY_ENV, "https://registry.npmjs.org")  # a mistaken setting
    origins = collector._mirror_origins()
    assert collector._token_for("https://registry.npmjs.org/x", origins) == ""
    monkeypatch.setenv(NPM_REGISTRY_ENV, NPM_MIRROR)
    origins = collector._mirror_origins()
    assert collector._token_for(f"{NPM_MIRROR}/x", origins) == TOKEN
    assert collector._token_for("https://npm.corp.example:444/x", origins) == ""
    assert collector._token_for("http://npm.corp.example/x", origins) == ""
    assert collector._token_for("https://pypi.org/pypi/x/json", origins) == ""


def test_without_a_mirror_a_request_is_what_it_always_was(monkeypatch):
    """The token alone sends nothing anywhere, and the request is the plain urlopen of before."""
    monkeypatch.setenv(REGISTRY_TOKEN_ENV, TOKEN)
    calls = []
    monkeypatch.setattr(collector.urllib.request, "urlopen",
                        lambda url, timeout: calls.append(url) or io.BytesIO(b"{}"))
    collector._open("https://registry.npmjs.org/x", timeout=5)
    assert calls == ["https://registry.npmjs.org/x"]  # a plain URL string: no header at all
    with pytest.raises(CollectionError, match="non-https"):
        collector._open("http://127.0.0.1:4873/x", timeout=5)


# --- the hook ------------------------------------------------------------------------------------

def _bash(command):
    return {"hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}}


def _report():
    return {"risk_level": "low", "risk_score": 0, "findings": [],
            "component": {"version": "4.17.21"}, "verdict": {"has_malicious_indicators": False}}


def _hook(command, environ, tmp_path, **options):
    calls: list[tuple[str, dict]] = []

    def scan(source, timeout, **kwargs):
        calls.append((source, kwargs))
        return _report()

    out = hook_response(_bash(command), scan=scan, environ=environ, home=tmp_path, **options)
    return out, calls


def test_a_package_from_the_mirror_is_checked_there(tmp_path):
    environ = {"NPM_CONFIG_REGISTRY": NPM_MIRROR + "/", NPM_REGISTRY_ENV: NPM_MIRROR,
               REGISTRY_TOKEN_ENV: TOKEN}
    out, calls = _hook("npm i lodash", environ, tmp_path)
    assert calls == [("npm:lodash", {"mirror": True})]
    assert "permissionDecision" not in out["hookSpecificOutput"]
    assert "(from the registry mirror)" in out["systemMessage"]
    assert TOKEN not in json.dumps(out)


def test_a_mirror_set_in_npmrc_counts_too(tmp_path):
    (tmp_path / ".npmrc").write_text(f"registry={NPM_MIRROR}\n", encoding="utf-8")
    out, calls = _hook("npm i lodash", {NPM_REGISTRY_ENV: NPM_MIRROR}, tmp_path)
    assert calls == [("npm:lodash", {"mirror": True})]


def test_a_pip_index_on_the_mirror_is_checked_there(tmp_path):
    environ = {"PIP_INDEX_URL": "https://user:pw@pypi.corp.example/artifactory/api/pypi/"
                                "pypi-remote/simple/", PYPI_INDEX_ENV: PYPI_MIRROR}
    out, calls = _hook("pip install requests==2.31.0", environ, tmp_path)
    assert calls == [("pypi:requests==2.31.0", {"mirror": True})]


@pytest.mark.parametrize("environ", [
    # another registry than the mirror
    {"NPM_CONFIG_REGISTRY": OTHER, NPM_REGISTRY_ENV: NPM_MIRROR},
    # the same host, another path
    {"NPM_CONFIG_REGISTRY": "https://npm.corp.example/artifactory/api/npm/npm-private",
     NPM_REGISTRY_ENV: NPM_MIRROR},
    # the mirror for npm, and another registry for yarn
    {"NPM_CONFIG_REGISTRY": NPM_MIRROR, "YARN_REGISTRY": OTHER, NPM_REGISTRY_ENV: NPM_MIRROR},
    # a mirror setting that cannot be used matches nothing
    {"NPM_CONFIG_REGISTRY": "http://npm.corp.example", NPM_REGISTRY_ENV: "http://npm.corp.example"},
])
def test_any_other_custom_registry_stays_unchecked(tmp_path, environ):
    out, calls = _hook("npm i lodash", environ, tmp_path)
    assert calls == []
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


@pytest.mark.parametrize("environ", [
    # the index is the mirror, an extra index is not
    {"PIP_INDEX_URL": f"{PYPI_MIRROR}/simple", "PIP_EXTRA_INDEX_URL": OTHER,
     PYPI_INDEX_ENV: PYPI_MIRROR},
    # only an extra index is the mirror: pip picks from PyPI and the mirror both
    {"PIP_EXTRA_INDEX_URL": f"{PYPI_MIRROR}/simple", PYPI_INDEX_ENV: PYPI_MIRROR},
    # the npm setting says nothing about Python
    {"PIP_INDEX_URL": f"{PYPI_MIRROR}/simple", NPM_REGISTRY_ENV: PYPI_MIRROR},
])
def test_a_python_index_besides_the_mirror_stays_unchecked(tmp_path, environ):
    out, calls = _hook("pip install requests", environ, tmp_path)
    assert calls == []
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_every_url_of_a_pip_conf_extra_index_line_counts(tmp_path):
    """Only the first URL of a line was read: a public index first hid the custom one."""
    conf = tmp_path / "pip.conf"
    conf.write_text(f"[global]\nextra-index-url = https://pypi.org/simple {OTHER}\n",
                    encoding="utf-8")
    out, calls = _hook("pip install requests", {"PIP_CONFIG_FILE": str(conf)}, tmp_path)
    assert calls == []
    assert "other.registry.invalid" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_in_ci_the_mirror_passes_and_any_other_registry_is_denied(tmp_path):
    mirror = {"NPM_CONFIG_REGISTRY": NPM_MIRROR, NPM_REGISTRY_ENV: NPM_MIRROR}
    out, calls = _hook("npm i lodash", mirror, tmp_path, strict=True, strict_by="CI")
    assert calls == [("npm:lodash", {"mirror": True})]
    assert out["hookSpecificOutput"].get("permissionDecision") != "deny"
    other = {"NPM_CONFIG_REGISTRY": OTHER, NPM_REGISTRY_ENV: NPM_MIRROR}
    out, calls = _hook("npm i lodash", other, tmp_path, strict=True, strict_by="CI")
    assert calls == []
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "registry" in out["systemMessage"]


def test_a_malicious_package_on_the_mirror_is_denied(tmp_path):
    environ = {"NPM_CONFIG_REGISTRY": NPM_MIRROR, NPM_REGISTRY_ENV: NPM_MIRROR}
    out = hook_response(_bash("npm i lodash"), environ=environ, home=tmp_path,
                        scan=lambda s, t, **k: {**_report(), "verdict": {
                            "has_malicious_indicators": True}, "findings": [
                            {"id": "ST-X", "title": "x", "severity": "high",
                             "threat_class": "malicious_indicator", "evidence": []}]})
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_a_package_from_the_public_registry_is_read_there_with_a_mirror_set(tmp_path):
    out, calls = _hook("npm i lodash", {NPM_REGISTRY_ENV: NPM_MIRROR}, tmp_path)
    assert calls == [("npm:lodash", {})]


def test_the_hook_keeps_a_mirror_verdict_apart(tmp_path, monkeypatch):
    monkeypatch.setenv("SKILLTOTAL_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv(NPM_REGISTRY_ENV, NPM_MIRROR)
    lookups, scans = [], []
    monkeypatch.setattr(collector, "resolve_release", lambda source, timeout=0, **kw: (
        lookups.append(kw) or collector.Release("npm:x@1.0.0")))
    monkeypatch.setattr(cli, "_hook_scan", lambda s, t, job=None, **kw: (
        scans.append((job["key"], kw)) or _report()))
    cli._hook_scan_cached("npm:x", 20, mirror=True)
    cli._hook_scan_cached("npm:x", 20)
    assert lookups == [{}, {"use_mirror": False}]
    assert scans == [(f"npm:x@1.0.0 via {NPM_MIRROR}", {"mirror": True}), ("npm:x@1.0.0", {})]


def test_only_a_mirror_check_gets_the_mirror_settings_and_token(tmp_path, monkeypatch):
    monkeypatch.setenv(NPM_REGISTRY_ENV, NPM_MIRROR)
    monkeypatch.setenv(REGISTRY_TOKEN_ENV, TOKEN)
    envs = []

    class _Proc:
        pid = 4242

    monkeypatch.setattr(hook_scan, "_spawn", lambda argv, **options: (
        envs.append(options["env"]) or _Proc()))
    for mirror in (False, True):
        check = hook_scan.RunningScan.start("npm:x@1.0.0", mirror=mirror)
        hook_scan.remove_tree(check.tmp)
    assert REGISTRY_TOKEN_ENV not in envs[0] and NPM_REGISTRY_ENV not in envs[0]
    assert envs[1][REGISTRY_TOKEN_ENV] == TOKEN and envs[1][NPM_REGISTRY_ENV] == NPM_MIRROR


def test_an_unusable_mirror_setting_is_said_in_the_console(monkeypatch):
    note = cli._hook_settings_note({NPM_REGISTRY_ENV: "https://u:s3cret@npm.corp.example"}, 100)
    assert f"{NPM_REGISTRY_ENV} is not a usable registry URL" in note
    assert "s3cret" not in note
