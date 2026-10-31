"""A marketplace .vsix is read by byte ranges: only what the engine reads is fetched, and anything
odd falls back to the whole file, streamed to disk under its own limit. Offline, with a stand-in
server."""

from __future__ import annotations

import gzip
import io
import json
import random
import struct
import zipfile

import pytest

from skilltotal import collector, engine
from skilltotal.collector import CollectionError, SizeLimitError
from tests.test_collector_marketplaces import (
    _OVSX_API,
    _VSM_PACKAGE,
    _VSM_QUERY,
    _gallery,
    _ovsx_doc,
    _ovsx_file,
    _Ranged,
    _Resp,
    _Transport,
)

_MANIFEST = {"name": "tiny", "publisher": "acme", "version": "1.2.3",
             "engines": {"vscode": "^1.80.0"}, "main": "./extension.js"}
_CDN = "https://acme.gallerycdn.vsassets.io/extensions/acme/tiny/1.2.3/1"
_ASSET = f"{_CDN}/Microsoft.VisualStudio.Services.VSIXPackage"
_SOURCE = "openvsx:acme.tiny@1.2.3"
_FILE = _ovsx_file("1.2.3")


def _native(size: int) -> bytes:
    """Incompressible bytes with a NUL early on, as an executable has."""
    return b"\x7fELF\0" + random.Random(1).randbytes(size)


def _pkg(extra: dict[str, bytes] | None = None, *,
         compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    files = {"extension.vsixmanifest": b"<PackageManifest/>", "[Content_Types].xml": b"<Types/>",
             "extension/package.json": json.dumps(_MANIFEST).encode(),
             "extension/extension.js": b"exports.activate = () => {};\n", **(extra or {})}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _with_binary(size: int = 4 * 1024 * 1024) -> bytes:
    return _pkg({"extension/resources/native-binary/claude": _native(size),
                 "extension/after.js": b"exports.after = 1;\n"})


def _patch_central(blob: bytes, entry: int, field: int, value: bytes) -> bytes:
    """``blob`` with bytes at offset ``field`` of central-directory record ``entry`` replaced."""
    at = -1
    for _ in range(entry + 1):
        at = blob.index(b"PK\x01\x02", at + 1)
    return blob[:at + field] + value + blob[at + field + len(value):]


@pytest.fixture
def serve(transport):
    def install(blob: bytes, answer=None) -> _Ranged:
        file = _Ranged(blob, answer)
        transport({("GET", f"{_OVSX_API}/1.2.3"): _Resp(_ovsx_doc("1.2.3")), ("GET", _FILE): file})
        return file
    return install


@pytest.fixture
def transport(monkeypatch):
    def install(routes: dict) -> _Transport:
        t = _Transport(routes)
        monkeypatch.setattr(collector, "_marketplace_send", t)
        return t
    return install


# ------------------------------------------------------------------ only what is read


def test_a_native_binary_is_never_fetched_and_the_report_says_so(serve):
    blob = _with_binary()
    file = serve(blob)
    report = engine.analyze(_SOURCE).to_dict()
    assert report["component"]["type"] == "vscode_extension"
    assert report["component"]["version"] == "1.2.3"
    assert file.whole == 0
    assert file.bytes_served() < len(blob) // 2
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        info = zf.getinfo("extension/resources/native-binary/claude")
    assert not file.served(info.header_offset + info.compress_size // 2)
    note = next(n for n in report["needs_review"] if n["title"] == "Binary files not read")
    assert note["category"] == "coverage"
    assert note["reason"].startswith("1 binary file in this package (4.0 MB in total;")
    assert "extension/resources/native-binary/claude" in note["reason"]


def test_a_binary_stays_as_a_small_placeholder_the_index_still_counts_as_binary(serve):
    serve(_with_binary())
    with collector.collect(_SOURCE) as ctx:
        placeholder = ctx.root / "extension/resources/native-binary/claude"
        assert 0 < placeholder.stat().st_size <= 8000
        assert placeholder.read_bytes().startswith(b"\x7fELF\0")
        assert (ctx.root / "extension/after.js").read_bytes() == b"exports.after = 1;\n"
        assert not list(ctx.root.parent.glob("*.vsix"))
        assert "1 binary file" in ctx.unpacked_note


def test_a_binary_install_script_is_still_reported_as_unread(serve):
    # Dropping the file would have dropped this note: the engine goes by what is on disk.
    manifest = {**_MANIFEST, "scripts": {"postinstall": "node ./setup.bin"}}
    serve(_pkg({"extension/package.json": json.dumps(manifest).encode(),
                "extension/setup.bin": _native(300_000)}))
    report = engine.analyze(_SOURCE).to_dict()
    assert any("postinstall" in n["reason"] and "setup.bin" in n["reason"]
               for n in report["needs_review"])


@pytest.mark.parametrize(("name", "content"), [
    ("extension/a.pyc", b"\0" * 9000),                # bytecode is reported, so it stays whole
    ("extension/nested.zip", b"PK\x03\x04" + b"\0" * 9000),  # the encrypted-archive check opens it
    ("extension/nuls.js", b"let a = 1;\0" + b"x" * 9000),    # Node runs it: the index reads it
    ("extension/wide.ps1", "Write-Host hi\n".encode("utf-16") + b"a\0" * 5000),  # a wide script
    ("extension/late.bin", b"a" * 9000 + b"\0"),      # a NUL past the sniff window is text
], ids=["bytecode", "zip", "js with a NUL", "utf-16 script", "late NUL"])
def test_what_the_engine_reads_is_kept_whole(serve, name, content):
    serve(_pkg({name: content}))
    with collector.collect(_SOURCE) as ctx:
        assert (ctx.root / name).read_bytes() == content
        assert ctx.unpacked_note is None


def test_an_executable_named_like_text_is_judged_by_its_content(serve):
    # The name decides nothing: a script named .node is read, a binary named .txt is not.
    serve(_pkg({"extension/run.node": b"require('child_process')\n",
                "extension/data.txt": _native(50_000)}))
    with collector.collect(_SOURCE) as ctx:
        assert (ctx.root / "extension/run.node").read_bytes().startswith(b"require")
        assert (ctx.root / "extension/data.txt").stat().st_size <= 8000


def test_visual_studio_marketplace_reads_its_cdn_and_keeps_the_public_url(transport):
    blob = _with_binary()
    file = _Ranged(blob)
    query = json.loads(_gallery(("1.2.3", None, False)))
    query["results"][0]["extensions"][0]["versions"][0]["assetUri"] = _CDN
    package = _VSM_PACKAGE.format(version="1.2.3")
    t = transport({("POST", _VSM_QUERY): _Resp(json.dumps(query).encode()), ("GET", _ASSET): file})
    with collector.collect("vscode:acme.tiny") as ctx:
        assert ctx.component.download_url == package
        assert "1 binary file" in ctx.unpacked_note
    assert package not in t.urls()
    assert file.whole == 0


def test_visual_studio_marketplace_without_an_asset_url_streams_the_gzip_package(transport):
    package = _VSM_PACKAGE.format(version="1.2.3")
    transport({("POST", _VSM_QUERY): _Resp(_gallery(("1.2.3", None, False))),
               ("GET", package): lambda: _Resp(gzip.compress(_with_binary()),
                                               headers={"Content-Encoding": "gzip"})})
    with collector.collect("vscode:acme.tiny") as ctx:
        assert "1 binary file" in ctx.unpacked_note
        assert (ctx.root / "extension/after.js").is_file()


def test_nearby_ranges_are_joined_and_requests_stay_few(serve):
    file = serve(_pkg({f"extension/m{i}.js": b"module.exports = 1;\n" * 50 for i in range(300)}))
    with collector.collect(_SOURCE) as ctx:
        assert (ctx.root / "extension/m299.js").is_file()
    assert len(file.spans) <= 4


def test_a_zip64_member_reads_like_any_other(serve):
    buf = io.BytesIO(_pkg())
    with zipfile.ZipFile(buf, "a") as zf, zf.open("extension/z.js", "w", force_zip64=True) as out:
        out.write(b"exports.z = 1;\n")
    file = serve(buf.getvalue())
    with collector.collect(_SOURCE) as ctx:
        assert (ctx.root / "extension/z.js").is_file()
    assert file.whole == 0


def test_bytes_not_fetched_are_never_read_as_zeros(transport, tmp_path):
    blob = _pkg()
    transport({("GET", _FILE): _Ranged(blob)})
    with collector._RemoteZip(_FILE, collector._OPEN_VSX, tmp_path / "p") as remote:
        remote.seek(0)
        assert remote.read(4) == b"PK\x03\x04"
        remote.seek(-22, 2)
        assert remote.read() == blob[-22:]
        assert remote.tell() == len(blob)
        assert remote.read(10) == b""


# ------------------------------------------------------------------ anything odd: the whole file


def _gzip_body(_n, body, headers):
    return _Resp(body, 206, {**headers, "Content-Encoding": "gzip"})


def _full_body(_n, body, headers):
    return _Resp(_pkg(), 200, {})


def _wrong_range(_n, body, headers):
    return _Resp(body, 206, {**headers, "Content-Range": "bytes 0-1/9"})


def _new_etag(n, body, headers):
    return _Resp(body, 206, {**headers, "ETag": f'"v{n}"'})


def _short_body(n, body, headers):
    return _Resp(body[:len(body) // 2 or None] if n > 1 else body, 206, headers)


def _server_error(n, body, headers):
    return _Resp(b"", 501, {})


@pytest.mark.parametrize("answer", [_gzip_body, _full_body, _wrong_range, _new_etag, _short_body,
                                    _server_error])
def test_a_server_that_does_not_serve_exact_ranges_falls_back_to_the_whole_file(serve, answer):
    file = serve(_with_binary(200_000), answer)
    with collector.collect(_SOURCE) as ctx:
        assert (ctx.root / "extension/after.js").is_file()
        assert ctx.unpacked_note.startswith("1 binary file")  # the report says the same
    assert file.whole == 1


def test_too_many_separate_ranges_fall_back(serve, monkeypatch):
    monkeypatch.setattr(collector, "_MAX_RANGE_REQUESTS", 2)
    file = serve(_with_binary())
    with collector.collect(_SOURCE) as ctx:
        assert (ctx.root / "extension/after.js").is_file()
    assert file.whole == 1


def test_more_to_fetch_than_the_limit_is_a_size_refusal(serve, monkeypatch):
    monkeypatch.setattr(collector, "_MAX_EXTENSION_BYTES", 2048)
    file = serve(_pkg({"extension/big.js": random.Random(2).randbytes(8192).hex().encode()}))
    with pytest.raises(SizeLimitError, match="exceeds the size limit") as exc:
        collector.collect(_SOURCE)
    assert exc.value.variable == "SKILLTOTAL_MAX_EXTENSION_MB"
    assert file.whole == 0  # the whole file is known to be over the limit: not downloaded


def test_overlapping_members_fall_back_and_are_never_read_by_range(serve):
    blob = _pkg({"extension/b.js": b"exports.b = 1;\n"})
    second_offset = struct.pack("<I", 0)
    file = serve(_patch_central(blob, 1, 42, second_offset))
    with pytest.raises(CollectionError):
        collector.collect(_SOURCE).cleanup()
    assert file.whole == 1


def test_an_offset_past_the_end_falls_back(serve):
    blob = _pkg()
    file = serve(_patch_central(blob, 1, 42, struct.pack("<I", len(blob) + 1000)))
    with pytest.raises(CollectionError):
        collector.collect(_SOURCE).cleanup()
    assert file.whole == 1


def test_a_size_that_lies_is_an_error_and_never_a_partial_scan(serve):
    # The central directory says 5 bytes; the member's checksum is of the real content.
    file = serve(_patch_central(_pkg(), 3, 24, struct.pack("<I", 5)))
    with pytest.raises(CollectionError, match="could not be"):
        collector.collect(_SOURCE)
    assert file.whole == 1


def test_a_compression_nobody_reads_here_falls_back(serve):
    file = serve(_pkg({"extension/a.js": b"exports.a = 1;\n" * 100},
                      compression=zipfile.ZIP_BZIP2))
    with collector.collect(_SOURCE) as ctx:
        assert (ctx.root / "extension/a.js").is_file()
    assert file.whole == 1


def test_a_path_out_of_the_package_is_refused(serve):
    serve(_pkg({"extension/../../evil.js": b"x"}))
    with pytest.raises(CollectionError, match="unsafe path"):
        collector.collect(_SOURCE)


def test_something_that_is_no_zip_is_refused(serve):
    serve(b"<html>not a package</html>" * 10)
    with pytest.raises(CollectionError, match="did not return a .vsix package"):
        collector.collect(_SOURCE)


# ------------------------------------------------------------------ limits


def test_a_compression_bomb_stops_at_the_extract_limit_with_no_download(serve, monkeypatch):
    monkeypatch.setattr(collector, "_MAX_EXTRACT_BYTES", 1024 * 1024)
    file = serve(_pkg({"extension/bomb.js": b"a" * (8 * 1024 * 1024)}))
    with pytest.raises(SizeLimitError, match="too large when extracted") as exc:
        collector.collect(_SOURCE)
    assert exc.value.variable == "SKILLTOTAL_MAX_EXTRACT_MB"
    assert file.whole == 0
    assert file.bytes_served() < 256 * 1024


@pytest.mark.parametrize("ranged", [True, False], ids=["ranges", "whole file"])
def test_binaries_do_not_count_toward_the_extract_limit(serve, monkeypatch, ranged):
    monkeypatch.setattr(collector, "_MAX_EXTRACT_BYTES", 1024 * 1024)
    serve(_with_binary(), None if ranged else _full_body)
    with collector.collect(_SOURCE) as ctx:
        assert "4.0 MB" in ctx.unpacked_note


def test_the_extension_limit_is_not_the_archive_limit(serve, monkeypatch):
    monkeypatch.setattr(collector, "_MAX_ARCHIVE_BYTES", 1024)
    serve(_with_binary(), _full_body)
    with collector.collect(_SOURCE) as ctx:
        assert ctx.component.version == "1.2.3"


def test_a_package_too_large_to_fetch_whole_still_scans_by_ranges(serve, monkeypatch):
    monkeypatch.setattr(collector, "_MAX_EXTENSION_BYTES", 1024 * 1024)
    file = serve(_with_binary())
    with collector.collect(_SOURCE) as ctx:
        assert (ctx.root / "extension/extension.js").is_file()
    assert file.whole == 0


def test_the_whole_file_goes_to_disk_in_pieces(monkeypatch):
    class Sink:
        largest = total = 0

        def write(self, piece: bytes) -> None:
            self.largest = max(self.largest, len(piece))
            self.total += len(piece)

    deadline = float("inf")
    for body, headers in ((b"x" * 5_000_000, {}),
                          (gzip.compress(b"\0" * 5_000_000), {"Content-Encoding": "gzip"})):
        sink = Sink()
        collector._read_bounded(_Resp(body, headers=headers), "u", sink, archive=True,
                                deadline=deadline)
        assert sink.total == 5_000_000
        assert sink.largest <= collector._READ_CHUNK


def test_source_notes_are_what_a_caller_of_collect_adds_itself(serve):
    serve(_with_binary())
    with collector.collect(_SOURCE) as ctx:
        titles = [n.title for n in engine.source_notes(ctx)]
    assert titles == ["Binary files not read"]
