"""MCP server: concurrent calls and cancellation, robust input, path and argument checks, the
compact summary answers, error hints, and the sweep of stale temporary folders."""

from __future__ import annotations

import io
import json
import os
import threading
import time
from pathlib import Path

import pytest

import skilltotal.mcp_server as mcp
from skilltotal.collector import CollectionError, SourceTooLargeError, collect
from skilltotal.mcp_server import (
    NOT_CHECKED,
    SUPPORTED_PROTOCOL_VERSIONS,
    TOOLS,
    handle_message,
    remove_stale_temp_dirs,
    serve,
    summarize_diff,
    summarize_report,
)

WAIT = 10  # seconds a test waits for a thread before it fails instead of hanging


def _call(name: str, arguments, msg_id=1) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "method": "tools/call",
            "params": {"name": name, "arguments": arguments}}


def _answer(name: str, arguments) -> dict:
    return handle_message(_call(name, arguments))["result"]


def _error_text(name: str, arguments) -> str:
    result = _answer(name, arguments)
    assert result["isError"] is True, result
    return result["content"][0]["text"]


class _Out:
    """A stdout the worker threads write to, which a test can wait on."""

    def __init__(self) -> None:
        self.lines: list[dict] = []
        self._changed = threading.Condition()

    def write(self, text: str) -> None:
        with self._changed:
            self.lines.extend(json.loads(line) for line in text.splitlines() if line)
            self._changed.notify_all()

    def flush(self) -> None:
        pass

    def ids(self) -> list:
        return [line.get("id") for line in self.lines]


@pytest.fixture
def fake_scans(monkeypatch):
    """``analyze`` replaced by a scan that waits for the test: each source gets an event the scan
    sets when it starts, and the scan returns once ``release`` is set."""

    class Scans:
        release = threading.Event()
        started: dict[str, threading.Event] = {}
        ran: list[str] = []

        def started_event(self, source: str) -> threading.Event:
            return self.started.setdefault(source, threading.Event())

    scans = Scans()

    class _Report:
        def __init__(self, source: str) -> None:
            self.source = source

        def to_dict(self) -> dict:
            return {"component": {"name": self.source}, "risk_score": 0, "findings": []}

    def analyze(source: str):
        scans.ran.append(source)
        scans.started_event(source).set()
        assert scans.release.wait(WAIT)
        return _Report(source)

    monkeypatch.setattr(mcp, "analyze", analyze)
    monkeypatch.setattr(mcp, "_checked_source", lambda source: source)
    return scans


# --- A1: calls on a pool, ping at once, cancellation ------------------------------------------


def test_a_ping_is_answered_while_a_scan_runs(fake_scans):
    out = _Out()

    def lines():
        yield json.dumps(_call("scan_component", {"source": "slow"}, msg_id=1))
        assert fake_scans.started_event("slow").wait(WAIT)
        yield json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"})
        # The ping is answered on the reading thread, while the scan still waits.
        assert out.ids() == [2]
        fake_scans.release.set()

    serve(lines(), out)
    # End of input waits for the running call, which is then answered.
    assert out.ids() == [2, 1]
    assert out.lines[1]["result"]["isError"] is False


def test_two_scans_run_at_once(monkeypatch):
    both = threading.Barrier(2, timeout=WAIT)

    class _Report:
        def to_dict(self) -> dict:
            return {"risk_score": 0, "findings": []}

    def analyze(source: str):
        both.wait()  # only passes when the other scan is running too
        return _Report()

    monkeypatch.setattr(mcp, "analyze", analyze)
    monkeypatch.setattr(mcp, "_checked_source", lambda source: source)
    out = _Out()
    serve([json.dumps(_call("scan_component", {"source": s}, msg_id=s)) for s in ("a", "b")],
          out)
    assert sorted(out.ids()) == ["a", "b"]
    assert all(line["result"]["isError"] is False for line in out.lines)


def test_a_cancelled_call_is_not_answered_and_a_queued_one_not_run(fake_scans):
    assert mcp.MAX_CONCURRENT_CALLS == 2
    out = _Out()

    def cancel(request_id):
        return json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled",
                           "params": {"requestId": request_id, "reason": "user"}})

    def lines():
        for n in (1, 2, 3):
            yield json.dumps(_call("scan_component", {"source": f"s{n}"}, msg_id=n))
        assert fake_scans.started_event("s1").wait(WAIT)
        assert fake_scans.started_event("s2").wait(WAIT)
        yield cancel(1)   # running: its answer is dropped
        yield cancel(3)   # queued behind the two workers: never started
        yield cancel(99)  # unknown: ignored
        yield json.dumps({"jsonrpc": "2.0", "id": 4, "method": "ping"})
        fake_scans.release.set()

    serve(lines(), out)
    assert out.ids() == [4, 2]
    assert sorted(fake_scans.ran) == ["s1", "s2"]


def test_a_cancel_after_the_answer_does_not_touch_a_later_call_with_that_id(fake_scans):
    fake_scans.release.set()
    out = _Out()

    def lines():
        yield json.dumps(_call("scan_component", {"source": "first"}, msg_id=7))
        deadline = time.monotonic() + WAIT
        while 7 not in out.ids() and time.monotonic() < deadline:
            time.sleep(0.01)
        yield json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled",
                          "params": {"requestId": 7}})
        yield json.dumps(_call("scan_component", {"source": "second"}, msg_id=7))

    serve(lines(), out)
    assert out.ids() == [7, 7]


# --- A2: bytes that are not UTF-8 ------------------------------------------------------------


def test_a_line_that_is_not_utf8_gets_a_parse_error_and_the_session_goes_on():
    stdin = io.BytesIO(
        b'{"jsonrpc":"2.0","id":24,"method":"ping","x":"\xff\xfe"}\n'
        b'{"jsonrpc":"2.0","id":25,"method":"ping"}\n'
        b'{"jsonrpc":"2.0","id":26,"method":"\xc3\xa9"}\n'  # a valid two-byte character
    )
    out = _Out()
    serve(stdin, out)
    assert out.ids() == [None, 25, 26]
    assert out.lines[0]["error"]["code"] == -32700
    assert out.lines[1]["result"] == {}
    assert out.lines[2]["error"]["code"] == -32601  # read as UTF-8, then an unknown method


# --- A3: local paths --------------------------------------------------------------------------


@pytest.fixture
def no_scan(monkeypatch):
    def analyze(source: str):
        raise AssertionError(f"scanned {source!r}")

    monkeypatch.setattr(mcp, "analyze", analyze)


@pytest.mark.parametrize("source", ["", "   "])
def test_an_empty_source_is_refused(no_scan, source):
    assert "must not be empty" in _error_text("scan_component", {"source": source})
    schema = TOOLS[0]["inputSchema"]["properties"]["source"]
    assert schema["minLength"] == 1


@pytest.mark.parametrize("source", ["~", ".", "some/folder", "..\\up", "~/skills/x"])
def test_a_relative_local_path_is_refused_with_an_example(no_scan, source):
    text = _error_text("scan_component", {"source": source})
    assert "absolute path" in text
    assert "For example" in text


def test_a_bare_name_is_pointed_at_its_registries(no_scan):
    assert "npm:lodash or pypi:lodash" in _error_text("scan_component", {"source": "lodash"})
    scoped = _error_text("scan_component", {"source": "@scope/tool"})
    assert "npm:@scope/tool" in scoped
    assert "pypi:@scope" not in scoped


def test_the_home_directory_a_folder_above_it_and_a_root_are_refused(no_scan, tmp_path):
    home = Path.home()
    assert "home directory" in _error_text("scan_component", {"source": str(home)})
    assert "above home" in _error_text("scan_component", {"source": str(home.parent)})
    root = _error_text("scan_component", {"source": tmp_path.anchor})
    assert "filesystem root" in root or "above home" in root
    assert "component's own folder" in root


# On Linux and macOS a backslash is part of a file name, so the backslash spellings are relative
# names there, refused as "not an absolute path"; only Windows reads them as a share or a device.
_WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="a backslash path is Windows syntax")


@pytest.mark.parametrize("source", [
    pytest.param("\\\\fileserver.invalid\\share\\skill", marks=_WINDOWS_ONLY),
    pytest.param("\\\\localhost\\C$\\Users\\me", marks=_WINDOWS_ONLY),
    pytest.param("\\\\127.0.0.1\\c$\\Users\\me", marks=_WINDOWS_ONLY),
    pytest.param("\\\\?\\C:\\Users\\me", marks=_WINDOWS_ONLY),
    pytest.param("\\\\.\\C:\\Users\\me", marks=_WINDOWS_ONLY),
    pytest.param("\\\\?\\UNC\\localhost\\C$\\Users\\me", marks=_WINDOWS_ONLY),
    pytest.param("\\\\?\\GLOBALROOT\\Device\\HarddiskVolume3\\Users\\me",
                 marks=_WINDOWS_ONLY),
    "//fileserver.invalid/share/skill",
    "//?/C:/",
])
def test_a_network_share_or_device_path_is_refused(no_scan, source):
    """A UNC or device path can name the home folder under a spelling the home check does not
    see through, or reach another machine (an SMB connection that can leak the user's NTLM hash):
    the server refuses it before resolving anything."""
    text = _error_text("scan_component", {"source": source})
    assert "network shares, device paths and alternate data streams are not scanned" in text
    assert "absolute path" not in text
    diff = _error_text("diff_components", {"old": "npm:x", "new": source})
    assert "network shares" in diff


@pytest.mark.skipif(os.name != "nt", reason="NTFS streams")
@pytest.mark.parametrize("suffix", ["::$INDEX_ALLOCATION", "::$DATA", ":stream"])
def test_an_ntfs_stream_of_a_folder_is_refused(no_scan, suffix):
    text = _error_text("scan_component", {"source": str(Path.home()) + suffix})
    assert "alternate data streams" in text


def test_another_name_for_the_home_folder_is_still_the_home_folder(no_scan, tmp_path, monkeypatch):
    """The home check compares folders by what the file system says they are: a link to the home
    folder (or a short 8.3 name) is refused like the home folder itself."""
    home = tmp_path / "home"
    (home / "skills" / "x").mkdir(parents=True)
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(home, target_is_directory=True)
    except OSError:
        try:
            import _winapi  # a junction needs no privilege

            _winapi.CreateJunction(str(home), str(alias))
        except (ImportError, OSError):
            pytest.skip("cannot create a link here")
    monkeypatch.setattr(mcp.Path, "home", classmethod(lambda cls: home))
    # resolve() would see through the link; the check must not depend on it.
    monkeypatch.setattr(mcp.Path, "resolve", lambda self, strict=False: self)
    assert "home directory" in _error_text("scan_component", {"source": str(alias)})
    assert "above home" in _error_text("scan_component", {"source": str(tmp_path)})
    assert mcp._same_or_inside(alias / "skills" / "x", home)
    assert not mcp._same_or_inside(tmp_path / "elsewhere", home)


def test_diff_checks_both_sides(no_scan):
    assert "absolute path" in _error_text("diff_components", {"old": "npm:x", "new": "."})


def test_registry_and_git_sources_are_not_path_checked(monkeypatch):
    seen = []

    def analyze(source: str):
        seen.append(source)
        raise CollectionError("offline")

    monkeypatch.setattr(mcp, "analyze", analyze)
    for source in ("npm:mcp-remote", "pypi:mcp==1.0", "https://github.com/o/r"):
        assert _error_text("scan_component", {"source": source}) == "offline"
    assert seen == ["npm:mcp-remote", "pypi:mcp==1.0", "https://github.com/o/r"]


def test_the_cli_does_not_suggest_pypi_for_a_scoped_name():
    with pytest.raises(CollectionError) as caught:
        collect("@no-such-scope-xyz/tool")
    assert "npm:@no-such-scope-xyz/tool" in str(caught.value)
    assert "pypi:" not in str(caught.value)


# --- A5: arguments ----------------------------------------------------------------------------


@pytest.mark.parametrize(("name", "arguments", "expected"), [
    ("scan_component", {"source": 123}, '"source" must be a string, not a number'),
    ("scan_component", {"source": ["x"]}, '"source" must be a string, not an array'),
    ("scan_component", {"source": "npm:x", "detail": "huge"}, '"detail" must be one of'),
    ("diff_components", {"old": "npm:x"}, '"new" is required'),
    ("list_rules", {"verbose": "true"}, '"verbose" must be true or false, not a string'),
    ("list_rules", {"ids": "ST-X"}, '"ids" must be an array of strings'),
    ("list_rules", {"query": 5}, '"query" must be a string'),
])
def test_a_wrong_argument_is_a_tool_error_with_an_example(no_scan, name, arguments, expected):
    text = _error_text(name, arguments)
    assert expected in text
    assert "For example:" in text


def test_a_null_optional_argument_is_no_argument():
    rules = json.loads(_answer("list_rules", {"verbose": None})["content"][0]["text"])
    assert "description" not in rules[0]


# --- A4: compact answers ----------------------------------------------------------------------


def _finding(rule, klass, severity="high", evidence=1):
    return {
        "id": rule, "threat_class": klass, "severity": severity, "title": f"title {rule}",
        "description": "long text " * 50, "recommendation": "more text " * 50,
        "evidence": [{"file": "src/a.js", "line_start": n, "line_end": n,
                      "snippet": "x" * 400 if n == 1 else f"line {n}"}
                     for n in range(1, evidence + 1)],
    }


def _report(findings, needs_review=()):
    return {
        "component": {"name": "pkg", "type": "npm_package", "source": "npm:pkg",
                      "version": "1.0.0", "download_url": "https://registry.example.test/pkg"},
        "risk_score": 40, "risk_level": "medium", "summary": "...",
        "verdict": {"level": "malicious", "headline": "Malicious indicators found",
                    "has_malicious_indicators": True, "reasons": []},
        "capabilities": {"network_egress": [{"file": "a"}] * 30, "shell_execution": []},
        "traits": [{"id": "T"} for _ in range(50)],
        "findings": findings,
        "needs_review": list(needs_review),
        "metadata": {"skilltotal_version": "9.9.9", "ruleset_version": 99,
                     "schema_version": "1.8"},
    }


def test_the_summary_puts_risk_first_and_stays_small():
    report = _report(
        [_finding("ST-CAP", "capability", "high", 9), _finding("ST-MAL", "malicious_indicator"),
         _finding("ST-RISK", "risky_construct", "medium", 5)],
        [{"category": "coverage", "title": "Minified bundle not analyzed", "reason": "1 file",
          "file": None, "line": None},
         {"category": "sensitive_path", "title": "Ambiguous secret-related words (3)",
          "reason": "...", "file": "README.md", "line": None}],
    )
    summary = summarize_report(report)
    assert summary["decision"] == "MALICIOUS - Malicious indicators found"
    assert summary["verdict"] == {"level": "malicious", "headline": "Malicious indicators found",
                                  "has_malicious_indicators": True}
    assert [f["rule"] for f in summary["why"]] == ["ST-MAL", "ST-RISK", "ST-CAP"]
    cap = summary["why"][2]
    assert len(cap["evidence"]) == 3 and cap["more_evidence"] == 6
    first = summary["why"][0]["evidence"][0]
    assert first.startswith("src/a.js:1  xxx") and first.endswith("...") and len(first) < 140
    assert summary["capabilities"] == ["network_egress", "shell_execution"]
    assert summary["counts"] == {
        "findings_by_threat_class": {"malicious_indicator": 1, "risky_construct": 1,
                                     "exposure": 0, "capability": 1},
        "needs_review": 2}
    assert summary["check_manually"] == ["Ambiguous secret-related words (3) (README.md)"]
    assert summary["not_checked"] == [*NOT_CHECKED, "Minified bundle not analyzed"]
    assert summary["component"]["version"] == "1.0.0"
    assert summary["engine"] == {"version": "9.9.9", "ruleset": 99, "report_schema": "1.8"}
    assert "traits" not in summary
    assert len(json.dumps(summary)) < len(json.dumps(report)) / 4


def test_the_diff_summary_names_the_verdict_change_and_risk_findings_only():
    from skilltotal.diff import diff_reports

    old = _report([_finding("ST-GONE", "risky_construct"), _finding("ST-CAP", "capability")])
    old["verdict"] = {"level": "low", "headline": "Low", "has_malicious_indicators": False}
    grown = _finding("ST-GROW", "risky_construct", evidence=2)
    old["findings"].append({**grown, "evidence": grown["evidence"][:1]})
    new = _report([_finding("ST-MAL", "malicious_indicator"), _finding("ST-NEWCAP", "capability"),
                   _finding("ST-CAP", "capability"), grown])
    summary = summarize_diff(old, new, diff_reports(old, new).to_dict())
    assert summary["verdict_changed"] is True
    assert summary["verdict_change"] == "LOW -> MALICIOUS"
    assert [f["rule"] for f in summary["new_risk_findings"]] == ["ST-MAL"]
    assert [f["rule"] for f in summary["risk_findings_with_new_evidence"]] == ["ST-GROW"]
    assert summary["risk_findings_with_new_evidence"][0]["evidence"] == ["src/a.js:2  line 2"]
    assert [f["id"] for f in summary["removed_risk_findings"]] == ["ST-GONE"]
    assert summary["not_checked"] == list(NOT_CHECKED)


def test_list_rules_filters_by_ids_and_query():
    def rules(arguments):
        return json.loads(_answer("list_rules", arguments)["content"][0]["text"])

    assert [r["id"] for r in rules({"ids": ["st-shell-pipe-exec", "ST-NOPE"]})] == [
        "ST-SHELL-PIPE-EXEC"]
    found = rules({"query": "PROMPT injection"})
    assert found and all("prompt injection" in (r["id"] + " " + r["title"]).lower()
                         for r in found)
    assert rules({"query": "zz-no-such-rule-zz"}) == []
    verbose = rules({"ids": ["ST-SHELL-PIPE-EXEC"], "verbose": True})
    assert "recommendation" in verbose[0]


# --- A6, A7: descriptions, titles, protocol ---------------------------------------------------


def test_tools_have_titles_and_say_how_to_read_the_answer():
    for tool in TOOLS:
        assert tool["title"]
    for tool in TOOLS[:2]:
        text = tool["description"]
        assert "verdict" in text and '"capability"' in text and "adds no risk" in text
        assert "CVEs" in text and "dependencies" in text
        assert tool["inputSchema"]["properties"]["detail"]["enum"] == ["summary", "full"]


def test_the_newest_protocol_version_is_offered():
    assert SUPPORTED_PROTOCOL_VERSIONS[0] == "2025-11-25"
    for version in ("2025-11-25", "2025-06-18", "2024-11-05"):
        resp = handle_message({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                               "params": {"protocolVersion": version}})
        assert resp["result"]["protocolVersion"] == version


# --- A8: error hints --------------------------------------------------------------------------


def test_a_size_limit_says_where_an_mcp_server_takes_its_setting(monkeypatch):
    def analyze(source: str):
        raise SourceTooLargeError("working tree is ~250 MB, which exceeds the 200 MB scan "
                                  "limit (o/r).", measured_mb=250, limit_mb=200)

    monkeypatch.setattr(mcp, "analyze", analyze)
    monkeypatch.delenv("SKILLTOTAL_MAX_CLONE_MB", raising=False)
    text = _error_text("scan_component", {"source": "https://github.com/o/r.git"})
    assert text.startswith("working tree is ~250 MB")
    assert '"env": {"SKILLTOTAL_MAX_CLONE_MB": "400"}' in text
    assert "https://github.com/o/r/tree/<ref>/<path>" in text


# --- A9: stale temporary folders --------------------------------------------------------------


def test_only_old_folders_with_the_engine_prefix_are_swept(tmp_path):
    now = time.time()
    old = now - mcp.STALE_TEMP_SECONDS - 60

    def folder(name: str, mtime: float) -> Path:
        path = tmp_path / name
        path.mkdir()
        (path / "f.txt").write_text("x", encoding="utf-8")
        os.utime(path, (mtime, mtime))
        return path

    stale = folder("skilltotal_stale", old)
    pack = stale / "repo" / ".git" / "objects"
    pack.mkdir(parents=True)
    (pack / "p.pack").write_text("x", encoding="utf-8")
    os.chmod(pack / "p.pack", 0o444)  # git's pack files are read-only
    os.utime(stale, (old, old))
    fresh = folder("skilltotal_fresh", now)
    other = folder("other_stale", old)
    lone_file = tmp_path / "skilltotal_file"
    lone_file.write_text("x", encoding="utf-8")
    os.utime(lone_file, (old, old))
    target = folder("target_stale", old)
    link = tmp_path / "skilltotal_link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        link = None  # no symlink privilege on this machine

    assert remove_stale_temp_dirs(str(tmp_path), now=now) == 1
    assert not stale.exists()
    assert fresh.exists() and other.exists() and lone_file.exists()
    assert (target / "f.txt").exists()
    if link is not None:
        assert os.path.lexists(link)


def test_the_sweep_never_raises():
    assert remove_stale_temp_dirs(str(Path(__file__).parent / "no-such-dir-xyz")) == 0
